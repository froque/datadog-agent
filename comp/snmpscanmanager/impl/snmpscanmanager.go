// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

// Package snmpscanmanagerimpl implements the snmpscanmanager component interface
package snmpscanmanagerimpl

import (
	"context"
	"encoding/json"
	"time"

	"github.com/DataDog/datadog-agent/comp/core/config"
	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	compdef "github.com/DataDog/datadog-agent/comp/def"
	snmpscan "github.com/DataDog/datadog-agent/comp/snmpscan/def"
	snmpscanmanager "github.com/DataDog/datadog-agent/comp/snmpscanmanager/def"
	"github.com/DataDog/datadog-agent/pkg/networkdevice/metadata"
	"github.com/DataDog/datadog-agent/pkg/persistentcache"
	"github.com/DataDog/datadog-agent/pkg/snmp/snmpparse"
)

const (
	scanWorkers   = 2
	scanQueueSize = 10000

	cacheKey = "snmp:scanned_devices"
)

// Requires defines the dependencies for the snmpscanmanager component
type Requires struct {
	compdef.In
	Lifecycle  compdef.Lifecycle
	Logger     log.Component
	Config     config.Component
	HttpClient ipc.HTTPClient
	Scanner    snmpscan.Component
}

// Provides defines the output of the snmpscanmanager component
type Provides struct {
	Comp snmpscanmanager.Component
}

// NewComponent creates a new snmpscanmanager component
func NewComponent(reqs Requires) (Provides, error) {
	scanManager := &snmpScanManagerImpl{
		log:         reqs.Logger,
		scanner:     reqs.Scanner,
		agentConfig: reqs.Config,
		httpClient:  reqs.HttpClient,

		scanQueue:      make(chan snmpscanmanager.ScanRequest, scanQueueSize),
		scannedDevices: make(scannedDevicesByIP),
	}
	scanManager.loadCache()

	reqs.Lifecycle.Append(compdef.Hook{
		OnStart: func(_ context.Context) error {
			scanManager.start()
			return nil
		},
		OnStop: func(_ context.Context) error {
			scanManager.stop()
			return nil
		},
	})

	return Provides{
		Comp: scanManager,
	}, nil
}

type snmpScanManagerImpl struct {
	log         log.Component
	scanner     snmpscan.Component
	agentConfig config.Component
	httpClient  ipc.HTTPClient

	scanQueue      chan snmpscanmanager.ScanRequest
	scannedDevices scannedDevicesByIP
}

type scannedDevicesByIP map[string]scannedDevice

type scannedDevice struct {
	DeviceIP  string    `json:"device_ip"`
	ScanEndTs time.Time `json:"scan_end_ts"`
}

func (m *snmpScanManagerImpl) start() {
	for i := 0; i < scanWorkers; i++ {
		go m.scanWorker()
	}
}

func (m *snmpScanManagerImpl) stop() {
	close(m.scanQueue)
}

// RequestScan queues a new scan request when the device has not been already scanned
func (m *snmpScanManagerImpl) RequestScan(req snmpscanmanager.ScanRequest) {
	_, exists := m.scannedDevices[req.DeviceIP]
	if exists {
		return
	}

	select {
	case m.scanQueue <- req:
		m.log.Infof("Queued scan request for device %s, scan queue size is %d",
			req.DeviceIP, len(m.scanQueue))
	default:
		m.log.Warnf("Dropping scan request for device %s, scan queue is full (%d)",
			req.DeviceIP, len(m.scanQueue))
	}
}

func (m *snmpScanManagerImpl) scanWorker() {
	for req := range m.scanQueue {
		err := m.processScanRequest(req)
		if err != nil {
			m.log.Errorf("Error processing scan request: %v", err)
		}
	}
}

func (m *snmpScanManagerImpl) processScanRequest(req snmpscanmanager.ScanRequest) error {
	instanceConfig, err := snmpparse.GetParamsFromAgent(req.DeviceIP, m.agentConfig, m.httpClient)
	if err != nil {
		return err
	}

	err = m.scanner.ScanDeviceAndSendData(instanceConfig, req.Namespace, metadata.DefaultScan)
	if err != nil {
		return err
	}

	m.scannedDevices[req.DeviceIP] = scannedDevice{
		DeviceIP:  req.DeviceIP,
		ScanEndTs: time.Now(),
	}
	m.writeCache()

	return nil
}

func (m *snmpScanManagerImpl) loadCache() {
	cacheValue, err := persistentcache.Read(cacheKey)
	if err != nil {
		m.log.Errorf("Error loading cache: %v", err)
		return
	}
	if cacheValue == "" {
		return
	}

	var scannedDevices []scannedDevice
	err = json.Unmarshal([]byte(cacheValue), &scannedDevices)
	if err != nil {
		m.log.Errorf("Error unmarshaling cache to JSON: %v", err)
		return
	}

	for _, device := range scannedDevices {
		m.scannedDevices[device.DeviceIP] = device
	}
}

func (m *snmpScanManagerImpl) writeCache() {
	scannedDevices := m.scannedDevices.toList()
	cacheValue, err := json.Marshal(scannedDevices)
	if err != nil {
		m.log.Errorf("Error marshaling cache to JSON: %v", err)
		return
	}

	err = persistentcache.Write(cacheKey, string(cacheValue))
	if err != nil {
		m.log.Errorf("Error writing cache: %v", err)
	}
}

func (s scannedDevicesByIP) toList() []scannedDevice {
	scannedDevices := make([]scannedDevice, 0, len(s))
	for _, device := range s {
		scannedDevices = append(scannedDevices, device)
	}
	return scannedDevices
}
