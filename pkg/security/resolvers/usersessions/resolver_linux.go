// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package usersessions holds model related to the user sessions resolver
package usersessions

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/hashicorp/golang-lru/v2/simplelru"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/security/probe/managerhelper"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model/usersession"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
)

// UserSessionKey describes the key to a user session
type UserSessionKey struct {
	ID      uint64
	Cursor  byte
	Padding [7]byte
}

// UserSessionData stores user session context data retrieved from the kernel
type UserSessionData struct {
	SessionType usersession.Type
	RawData     string
}

// UnmarshalBinary unmarshalls a binary representation of itself
func (e *UserSessionData) UnmarshalBinary(data []byte) error {
	if len(data) < 256 {
		return model.ErrNotEnoughSpace
	}

	e.SessionType = usersession.Type(data[0])
	e.RawData += model.NullTerminatedString(data[1:240])
	return nil
}

// incrementalFileReader is used to read a file incrementally
type incrementalFileReader struct {
	path               string
	f                  *os.File
	offset             int64
	mu                 sync.Mutex
	ino                uint64
	readFromJournalctl bool
	// chan to stop journalctl
	stopReading chan struct{} // make(chan struct{}, 1)
	// journalctl cursor - points to the last read journal entry
	journalCursor string
}

// SSHSessionKey describes the key to a ssh session in the LRU
type SSHSessionKey struct {
	IP   string // net.IP.String()
	Port string
}

// SSHSessionValue describes the value to a ssh session in the LRU
type SSHSessionValue struct {
	AuthenticationMethod int
	PublicKey            string
}

type sshSessionParsed struct {
	Mu  sync.Mutex
	Lru *simplelru.LRU[SSHSessionKey, SSHSessionValue]
}

// Resolver is used to resolve the user sessions context
type Resolver struct {
	sync.RWMutex
	userSessions *simplelru.LRU[uint64, *model.UserSessionContext]

	userSessionsMap *ebpf.Map

	sshLogReader     *incrementalFileReader
	SSHSessionParsed sshSessionParsed
}

// NewResolver returns a new instance of Resolver
func NewResolver(cacheSize int) (*Resolver, error) {
	lru, err := simplelru.NewLRU[uint64, *model.UserSessionContext](cacheSize, nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't create User Session resolver cache: %v", err)
	}

	return &Resolver{
		userSessions: lru,
	}, nil
}

// Start initializes the eBPF map of the resolver
func (r *Resolver) Start(manager *manager.Manager) error {
	r.Lock()
	defer r.Unlock()

	m, err := managerhelper.Map(manager, "user_sessions")
	if err != nil {
		return fmt.Errorf("couldn't start user session resolver: %v", err)
	}
	r.userSessionsMap = m

	// start the resolver for ssh sessions
	err = r.StartSSHUserSessionResolver()
	if err != nil {
		return err
	}
	return nil
}

// ResolveUserSession returns the user session associated to the provided ID
func (r *Resolver) ResolveUserSession(id uint64) *model.UserSessionContext {
	if id == 0 {
		return nil
	}

	r.Lock()

	defer r.Unlock()

	// is this session already in cache ?
	if session, ok := r.userSessions.Get(id); ok {
		return session
	}

	// lookup the session in kernel space
	key := UserSessionKey{
		ID:     id,
		Cursor: 1,
	}

	value := UserSessionData{}
	err := r.userSessionsMap.Lookup(&key, &value)
	for err == nil {
		key.Cursor++
		err = r.userSessionsMap.Lookup(&key, &value)
	}
	if key.Cursor == 1 && err != nil {
		// the session doesn't exist, leave now
		return nil
	}

	ctx := &model.UserSessionContext{
		ID:          id,
		SessionType: int(value.SessionType),
	}
	// parse the content of the user session context
	err = json.Unmarshal([]byte(value.RawData), ctx)
	if err != nil {
		seclog.Debugf("failed to parse user session data: %v", err)
		return nil
	}

	ctx.Resolved = true

	// cache resolved context
	r.userSessions.Add(id, ctx)
	return ctx
}

// Init opens the file and sets the initial offset
func (ifr *incrementalFileReader) Init(f *os.File) error {
	if ifr.f != nil {
		return nil
	}

	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		seclog.Warnf("Fail to stat log file: %v", err)
		return err
	}

	ifr.offset = st.Size()

	ifr.f = f
	ifr.ino = inodeOf(st)
	_, err = ifr.f.Seek(ifr.offset, io.SeekStart)
	if err != nil {
		ifr.close(false)
		ifr.f = nil
	}
	return err
}

// startReading start to parse the potential ssh session and store them in the LRU
func (r *Resolver) startReading() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	r.sshLogReader.readFromJournalctl = true
	switch r.sshLogReader.readFromJournalctl {
	case true:
		for {
			select {
			case <-r.sshLogReader.stopReading:
				fmt.Print("WE stop\n")
				return
			case <-ticker.C:
				r.sshLogReader.mu.Lock()
				err := r.sshLogReader.resolveFromJournalctl(&r.SSHSessionParsed)
				if err != nil {
					seclog.Errorf("failed to read journalctl: %v", err)
				}
				r.sshLogReader.mu.Unlock()

			}
		}
	case false:
		for {
			select {
			case <-r.sshLogReader.stopReading:
				return
			case <-ticker.C:
				r.sshLogReader.mu.Lock()
				err := r.sshLogReader.resolveFromLogFile(&r.SSHSessionParsed)
				if err != nil {
					seclog.Errorf("failed to read ssh log lines: %v", err)
				}
				r.sshLogReader.mu.Unlock()

			}
		}
	}
}

func parseSSHLogLine(line string, sshSessionParsed *sshSessionParsed) error {
	type SSHLogLine struct {
		Date      string
		Hostname  string
		Service   string
		Remaining string
	}
	type SSHParsedLine struct {
		AuthentificationMethod string
		User                   string
		IP                     string
		Port                   string
		SSHVersion             string
		Remaining              string
	}
	// separate the line into words
	words := strings.Fields(line)
	sshLogLine := SSHLogLine{}
	if len(words) < 5 {
		return fmt.Errorf("not enough words in line\n")
	}
	switch {
	// We saw two different types of logs, so we try to parse both
	// We use HasPrefix because sshd is followed by its PID : sshd[pid]
	case strings.HasPrefix(words[2], "sshd"):
		sshLogLine = SSHLogLine{
			Date:      words[0],
			Hostname:  words[1],
			Service:   words[2],
			Remaining: strings.Join(words[3:], " "),
		}
	case strings.HasPrefix(words[4], "sshd"):
		sshLogLine = SSHLogLine{
			Date:      words[2],
			Hostname:  words[3],
			Service:   words[4],
			Remaining: strings.Join(words[5:], " "),
		}
	default:
		return fmt.Errorf("can't find sshd")
	}
	// if the service is "sshd" and the line starts with "Accepted" it's the beginning of an ssh session
	if strings.HasPrefix(sshLogLine.Service, "sshd") && strings.HasPrefix(sshLogLine.Remaining, "Accepted") {
		// One example of line is: "Accepted publickey for lima from 192.168.5.2 port 38835 ssh2: ED25519 SHA256:J3I5W45pnQtan5u0m27HWzyqAMZfTbG+nRet/pzzylU"
		// Get the infos like that : Accepted <authentification method> for <username> from <ip> port <port> <ssh version> <Remaining (hash)>

		sshWords := strings.Split(sshLogLine.Remaining, " ")
		if len(sshWords) < 9 {
			return fmt.Errorf("not enough words in line\n")
		}
		sshParsedLine := SSHParsedLine{
			AuthentificationMethod: sshWords[1],
			User:                   sshWords[3],
			IP:                     sshWords[5],
			Port:                   sshWords[7],
			SSHVersion:             sshWords[8],
			Remaining:              strings.Join(sshWords[9:], " "),
		}
		// We compare port and IP to ensure that the line is the one we want
		// Convert string IP to net.IP and compare normalized values
		parsedIP := net.ParseIP(sshParsedLine.IP)

		// We store every session in the LRU cache
		var authType usersession.AuthType
		var publicKey string
		switch sshParsedLine.AuthentificationMethod {
		case "publickey":
			authType = usersession.SSHAuthMethodPublicKey
			// Here Parse the Public Key which can be ED25519 SHA256:J3I5W45pnQtan5u0m27HWzyqAMZfTbG+nRet/pzzylU
			sshParsedLine.Remaining = strings.Split(sshParsedLine.Remaining, ":")[1]
			publicKey = sshParsedLine.Remaining
		case "password":
			authType = usersession.SSHAuthMethodPassword
		// Other types not implemented yet
		default:
			authType = usersession.SSHAuthMethodUnknown
		}
		key := SSHSessionKey{
			IP:   parsedIP.String(),
			Port: sshParsedLine.Port,
		}
		value := SSHSessionValue{
			AuthenticationMethod: int(authType),
			PublicKey:            publicKey,
		}
		sshSessionParsed.Mu.Lock()

		sshSessionParsed.Lru.Add(key, value)
		sshSessionParsed.Mu.Unlock()
		return nil
	}
	return fmt.Errorf("not an ssh session log line")
}

// resolveFromLogFile read all the lines that have been added since the last call without reopening the file.
// Return new lines, the byte offsets at the end of each line, and an error.
func (ifr *incrementalFileReader) resolveFromLogFile(sshSessionParsed *sshSessionParsed) error {
	if err := ifr.reloadIfRotated(); err != nil {
		return err
	}

	st, err := ifr.f.Stat()
	if err != nil {
		return err
	}

	if st.Size() == ifr.offset {
		return nil
	}
	// If the file is truncated, we restart from the beginning
	if st.Size() < ifr.offset {
		ifr.offset = 0
		if _, err := ifr.f.Seek(0, io.SeekStart); err != nil {
			return err
		}
	} else {
		// If the file is not truncated, we seek to the offset
		if _, err := ifr.f.Seek(ifr.offset, io.SeekStart); err != nil {
			return err
		}
	}

	sc := bufio.NewScanner(ifr.f)
	for sc.Scan() {
		line := sc.Text()
		parseSSHLogLine(line, sshSessionParsed)
	}
	newOffset, err := ifr.f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	ifr.offset = newOffset
	return err
}

// Lock ifr.mu
func (ifr *incrementalFileReader) resolveFromJournalctl(sshSessionParsed *sshSessionParsed) error {
	// Open the systemd journal
	journal, err := sdjournal.NewJournal()
	if err != nil {
		seclog.Errorf("failed to open systemd journal: %v", err)
		return err
	}
	defer journal.Close()

	// Add multiple match patterns to be permissive - these will be OR'ed
	// Try different ways sshd might appear in the journal
	journal.AddMatch("SYSLOG_IDENTIFIER=sshd")
	journal.AddDisjunction()
	journal.AddMatch("_SYSTEMD_UNIT=sshd.service")
	journal.AddDisjunction()
	journal.AddMatch("_COMM=sshd")
	// Seek using cursor if we have one, otherwise start from beginning
	if ifr.journalCursor != "" {
		if err := journal.SeekCursor(ifr.journalCursor); err != nil {
			seclog.Warnf("failed to seek to cursor %s: %v, will start from beginning", ifr.journalCursor, err)
			// Cursor invalid (maybe journal was rotated), start from beginning
			if err := journal.SeekHead(); err != nil {
				seclog.Errorf("failed to seek to head: %v", err)
				return err
			}
		} else {
			// We skip the first entry because it's the one we already processed
			_, err := journal.Next()
			if err != nil {
				seclog.Warnf("failed to skip first entry: %v", err)
				return err
			}
		}
	} else {
		// No cursor yet, start from the beginning
		if err := journal.SeekHead(); err != nil {
			seclog.Warnf("failed to seek to head: %v", err)
		}
	}

	linesProcessed := 0
	maxLinesToProcess := 10000 // Limit to avoid infinite loop

	// Iterate through journal entries
	for linesProcessed < maxLinesToProcess {
		n, err := journal.Next()
		if err != nil {
			seclog.Warnf("error iterating journal (processed %d lines): %v", linesProcessed, err)
			break // Don't fail completely, just stop reading
		}
		if n == 0 {
			break
		}

		linesProcessed++

		entry, err := journal.GetEntry()
		if err != nil {
			// Continue on error, don't fail the whole process
			seclog.Warnf("failed to get journal entry: %v", err)
			continue
		}

		timestamp := time.Unix(0, int64(entry.RealtimeTimestamp)*1000)

		message := entry.Fields["MESSAGE"]
		if message == "" {
			continue
		}

		// Reconstruct a log line in the format expected by parseSSHLogLine
		hostname := entry.Fields["_HOSTNAME"]
		if hostname == "" {
			hostname = "localhost"
		}
		pid := entry.Fields["_PID"]
		if pid == "" {
			pid = "0"
		}

		// Format the line to match what parseSSHLogLine expects
		dateStr := timestamp.Format("2006-01-02T15:04:05-0700")
		// Build log line
		line := fmt.Sprintf("%s %s sshd[%s]: %s",
			dateStr,
			hostname,
			pid,
			message,
		)

		// Parse the SSH log line
		err = parseSSHLogLine(line, sshSessionParsed)
		if err != nil {
			// Not an SSH session line, skip
			continue
		}
	}
	// Capture the final cursor position
	lastCursor, err := journal.GetCursor()
	if err != nil {
		seclog.Debugf("failed to get final cursor: %v", err)
	}
	// Save cursor to avoid re-reading these entries
	ifr.journalCursor = lastCursor

	return nil
}

// close closes the file.
// The lock of IncrementalFileReader must be held
func (ifr *incrementalFileReader) close(closeReader bool) error {
	var err error
	if ifr.f != nil {
		err = ifr.f.Close()
		ifr.f = nil
	}
	if closeReader {
		// Stop the reader
		ifr.stopReading <- struct{}{}
	}

	return err
}

// inodeOf get the inode of the file.
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// reloadIfRotated reopens the file if the inode has changed.
func (ifr *incrementalFileReader) reloadIfRotated() error {
	curSt, err := os.Stat(ifr.path)
	if err != nil {
		return err
	}
	curIno := inodeOf(curSt)
	if curIno != 0 && ifr.ino != 0 && curIno != ifr.ino {
		// The file has been rotated
		if ifr.f != nil {
			_ = ifr.close(false)
			ifr.f = nil
		}
		f, err := os.Open(ifr.path)
		if err != nil {
			ifr.close(false)
			ifr.f = nil
			return err
		}
		ifr.f = f
		ifr.ino = curIno

		// We restart from the beginning because it's a new file
		ifr.offset = 0
	}
	return nil
}

// StartSSHUserSessionResolver initializes the ssh log reader by looking for the available file, opening it and setting up the initial offset
// Lock must be held
func (r *Resolver) StartSSHUserSessionResolver() error {
	var err error

	// Initialize the SSH session LRU cache (needed in all cases)
	r.SSHSessionParsed.Lru, err = simplelru.NewLRU[SSHSessionKey, SSHSessionValue](100, nil)
	if err != nil {
		seclog.Errorf("couldn't create SSH Session LRU cache: %v", err)
		return err
	}

	// Try to find the ssh log file
	possibleLogPaths := []string{
		"/var/log/auth.log", // Debian/Ubuntu
		"/var/log/secure",   // RHEL/CentOS/Fedora
		"/var/log/messages", // openSUSE/autres
	}
	path := ""
	for _, possiblePath := range possibleLogPaths {
		_, err = os.Stat(possiblePath)
		if err == nil {
			path = possiblePath
			break
		}
	}
	// Initialize the SSH log reader
	r.sshLogReader = &incrementalFileReader{
		path:        path,
		stopReading: make(chan struct{}, 1),
	}
	// If there is no log file, we use journalctl (atm we do nothing)
	if path == "" {
		// // Don't want to continue in case there is no log file, use journalctl instead
		r.sshLogReader.readFromJournalctl = true
		go r.startReading()
		return nil
	}

	r.sshLogReader.readFromJournalctl = false
	// Now we can open the file if there is one
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		seclog.Errorf("failed to open ssh log file: %v", err)
		return err
	}
	if err := r.sshLogReader.Init(f); err != nil {
		seclog.Errorf("failed to init ssh log reader: %v", err)
		if f != nil {
			f.Close()
		}
		return err
	}
	go r.startReading()
	// Note: the file is not closed here, as the sshLogReader manage it
	return nil
}

// ResolveSSHUserSession resolves the ssh user session from the auth log
func (r *Resolver) ResolveSSHUserSession(ctx *model.UserSessionContext) *model.UserSessionContext {
	id := ctx.ID
	if id == 0 {
		return nil
	}

	r.Lock()

	defer r.Unlock()

	key := SSHSessionKey{
		IP:   ctx.SSHClientIP.IP.String(),
		Port: strconv.Itoa(ctx.SSHPort),
	}
	r.SSHSessionParsed.Mu.Lock()
	value, ok := r.SSHSessionParsed.Lru.Get(key)
	r.SSHSessionParsed.Mu.Unlock()
	if !ok {
		ctx.Resolved = true
		return nil
	}
	ctx.SSHAuthMethod = int(value.AuthenticationMethod)
	ctx.SSHPublicKey = value.PublicKey
	ctx.Resolved = true
	return ctx
}

// Close closes the resolver
func (r *Resolver) Close() {
	r.Lock()

	defer r.Unlock()

	if r.sshLogReader != nil {
		r.sshLogReader.mu.Lock()
		defer r.sshLogReader.mu.Unlock()
		_ = r.sshLogReader.close(true)
	}
}
