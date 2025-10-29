#ifndef _HOOKS_MOUNT_H_
#define _HOOKS_MOUNT_H_

#include "constants/syscall_macro.h"
#include "helpers/events_predicates.h"
#include "helpers/filesystem.h"
#include "helpers/syscalls.h"

#define REPEAT32(M) \
  M(00) M(01) M(02) M(03) M(04) M(05) M(06) M(07) \
  M(08) M(09) M(10) M(11) M(12) M(13) M(14) M(15) \
  M(16) M(17) M(18) M(19) M(20) M(21) M(22) M(23) \
  M(24) M(25) M(26) M(27) M(28) M(29) M(30) M(31)


/*
    How the mount cache works:

    When there are multiple mounts being created in a single syscall, the mounts appear out of order
    in functions like `attach_mnt` and `__attach_mnt`, such that the children mounts are created before the parents.
    This means that we can't resolve their paths until the entire tree is fully built.

    In order to go around that, a cache with pointers to all the mounts was created so that we're able to know which
    mounts were created during the entire syscall, to resolve them when the syscall returns and is the mount tree
    is fully constructed.

    The cache works as follows:
    - A u64 counter (`mount_cache_selector`) exists as a "global variable". This is only incremented
    - When a new syscall happens that needs this counter, we modulo that with the available mount caches to get a cache
    - This cache should be free, but if it's not, the code loops over all the other caches to see if there's something free
    - If there's nothing free, we get a -1, signalling the operation was unsuccessful.

    The point of having this dual mechanism is that looping over all the caches is expensive, and the modulo allows us
    to likely hit a free cache in the first attempt.

    The cache ID is of the current syscall is then saved to `syscall_cache_id` and is used to identify this syscall
    in the next hooks, such as `attach_mnt`.

    When we finally hit the syscall exit hook, we need to process the all the mounts but there's a problem: Dentry
    resolution is a long operation, and we can't perform it in the hook due to eBPF constraints, so one tail
    call happens for each mount.



    Any unsuccessful operation is reported to the userspace so that it manually synchronizes its cache
*/


struct mount_cache_t* __attribute__((always_inline)) get_mount_cache_from_id(long long id) {
    struct mount_cache_t* cache = bpf_map_lookup_elem(&mount_cache, &id);
    return cache;
}

// Add a mount to the cache, return the position where it was added
// or -1 in the case there wasn't enough space in the cache
long long __attribute__((always_inline)) mount_cache_add_mount(struct mount_cache_t* cache, struct mount* mnt) {
    if(cache->cur_pos >= MOUNT_CACHE_SIZE - 1) {
        return -1;
    }

    cache->cur_pos += 1;

    u32 pos = (u32)cache->cur_pos;

    if (pos >= MOUNT_CACHE_SIZE) {
        return -1;
    }

    cache->mounts[pos] = mnt;
    return pos;
}

long long __attribute__((always_inline)) mount_cache_add_mount_with_id(long long id, struct mount* mnt) {
    struct mount_cache_t* cache = get_mount_cache_from_id(id);
    if (cache == NULL) {
        return -1;
    }

    return mount_cache_add_mount(cache, mnt);
}

// Signal that the cache isn't in use anymore
void __attribute__((always_inline)) put_mount_cache(u64 id) {
    struct mount_cache_t* entry = bpf_map_lookup_elem(&mount_cache, &id);
    if (entry == NULL) {
        return;
    }
    __sync_val_compare_and_swap(&(entry->in_use), 1, 0);
    entry->cur_pos = 0;
}

// Tries to get a free mount cache id. Returns -1 if failed
// Pass a pointer to a mount_cache_t pointer if you also want it to get filled with a pointer to the cache struct
// Otherwise pass NULL
int __attribute__((always_inline)) reserve_mount_cache() {
    u32 key = 0;
    u64* id = bpf_map_lookup_elem(&mount_cache_selector, &key);
    if (!id) {
        return -1;
    }

    int i;
    struct mount_cache_t* entry;
    for(i = 0; i != NR_MOUNT_CACHES; ++i) {
        u64 key = __sync_fetch_and_add(id, 1);
        key %= NR_MOUNT_CACHES;
        entry = bpf_map_lookup_elem(&mount_cache, &key);
        // Should never happen
        if(entry == NULL) {
            return -1;
        }
        int r = __sync_val_compare_and_swap(&(entry->in_use), 0, 1);
        if (r == 0) {
            return key;
        }
    }

    return -1;
}

HOOK_ENTRY("mnt_want_write")
int hook_mnt_want_write(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall_with(mnt_want_write_predicate);
    if (!syscall) {
        return 0;
    }

    struct vfsmount *mnt = (struct vfsmount *)CTX_PARM1(ctx);

    switch (syscall->type) {
    case EVENT_UTIME:
        if (syscall->setattr.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->setattr.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_CHMOD:
        if (syscall->setattr.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->setattr.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_CHOWN:
        if (syscall->setattr.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->setattr.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_RENAME:
        if (syscall->rename.src_file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->rename.src_file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        syscall->rename.target_file.path_key.mount_id = syscall->rename.src_file.path_key.mount_id;
        break;
    case EVENT_RMDIR:
        if (syscall->rmdir.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->rmdir.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_UNLINK:
        if (syscall->unlink.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->unlink.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_SETXATTR:
        if (syscall->xattr.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->xattr.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_REMOVEXATTR:
        if (syscall->xattr.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->xattr.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    }
    return 0;
}

int __attribute__((always_inline)) trace__mnt_want_write_file(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall_with(mnt_want_write_file_predicate);
    if (!syscall) {
        return 0;
    }

    struct file *file = (struct file *)CTX_PARM1(ctx);
    struct vfsmount *mnt;
    bpf_probe_read(&mnt, sizeof(mnt), &get_file_f_path_addr(file)->mnt);

    switch (syscall->type) {
    case EVENT_CHOWN:
        if (syscall->setattr.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->setattr.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_SETXATTR:
        if (syscall->xattr.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->xattr.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_REMOVEXATTR:
        if (syscall->xattr.file.path_key.mount_id > 0) {
            return 0;
        }
        syscall->xattr.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    }
    return 0;
}

HOOK_ENTRY("mnt_want_write_file")
int hook_mnt_want_write_file(ctx_t *ctx) {
    return trace__mnt_want_write_file(ctx);
}

// mnt_want_write_file_path was used on old kernels (RHEL 7)
HOOK_ENTRY("mnt_want_write_file_path")
int hook_mnt_want_write_file_path(ctx_t *ctx) {
    return trace__mnt_want_write_file(ctx);
}

HOOK_SYSCALL_COMPAT_ENTRY3(mount, const char *, source, const char *, target, const char *, fstype) {
    bpf_printk("-> mount()");
    struct syscall_cache_t syscall = {
        .type = EVENT_MOUNT,
    };

    syscall.mount.syscall_cache_id = reserve_mount_cache();
    bpf_printk("MOUNT CACHE ID : %d", syscall.mount.syscall_cache_id);

    collect_syscall_ctx(&syscall, SYSCALL_CTX_ARG_STR(0) | SYSCALL_CTX_ARG_STR(1) | SYSCALL_CTX_ARG_STR(2), (void *)source, (void *)target, (void *)fstype);
    cache_syscall(&syscall);

    return 0;
}

HOOK_SYSCALL_ENTRY1(unshare, unsigned long, flags) {
    bpf_printk("-> unshare()");
    // unshare is only used to propagate mounts created when a mount namespace is copied
    if (!(flags & CLONE_NEWNS)) {
        return 0;
    }

    struct syscall_cache_t syscall = {
        .type = EVENT_UNSHARE_MNTNS,
    };

    cache_syscall(&syscall);

    return 0;
}

HOOK_SYSCALL_EXIT(unshare) {
    bpf_printk("<- ret unshare()");
    pop_syscall(EVENT_UNSHARE_MNTNS);
    return 0;
}

void __attribute__((always_inline)) fill_mount_fields(struct syscall_cache_t *syscall, struct mount_fields_t *mfields) {
    mfields->root_key = syscall->mount.root_key;
    mfields->mountpoint_key = syscall->mount.mountpoint_key;
    mfields->device = syscall->mount.device;
    mfields->bind_src_mount_id = syscall->mount.bind_src_mount_id;
    mfields->ns_inum = syscall->mount.ns_inum;
    mfields->mount_id_unique = syscall->mount.mount_id_unique;
    mfields->parent_mount_id_unique = syscall->mount.parent_mount_id_unique;
    mfields->bind_src_mount_id_unique = syscall->mount.bind_src_mount_id_unique;
    bpf_probe_read_str(&mfields->fstype, sizeof(mfields->fstype), (void *)syscall->mount.fstype);
}

int __attribute__((always_inline)) send_detached_event(void *ctx, struct syscall_cache_t *syscall) {
    struct mount_event_t event = {
        .syscall.retval = 0,
        .syscall_ctx.id = syscall->ctx_id,
        .source = SOURCE_OPEN_TREE,
        .mountfields.visible = false,
        .mountfields.detached = true,
    };

    if (syscall->type == EVENT_FSMOUNT) {
        event.source = SOURCE_FSMOUNT;
    }

    fill_mount_fields(syscall, &event.mountfields);
    struct proc_cache_t *entry = fill_process_context(&event.process);
    fill_cgroup_context(entry, &event.cgroup);
    fill_span_context(&event.span);

    send_event(ctx, EVENT_MOUNT, event);

    return 0;
}

void __attribute__((always_inline)) handle_new_mount(void *ctx, struct syscall_cache_t *syscall, enum TAIL_CALL_PROG_TYPE prog_type, bool detached) {
    // populate the root dentry key
    struct dentry *root_dentry = get_vfsmount_dentry(get_mount_vfsmount(syscall->mount.newmnt));
    syscall->mount.root_key.mount_id = get_mount_mount_id(syscall->mount.newmnt);
    syscall->mount.mount_id_unique = get_mount_mount_id_unique(syscall->mount.newmnt);
    syscall->mount.root_key.ino = get_dentry_ino(root_dentry);
    update_path_id(&syscall->mount.root_key, 0, 0);

    bpf_printk("handle_new_mount. id = %d", syscall->mount.root_key.mount_id);
    if(!detached) {
        // populate the mountpoint dentry key
        syscall->mount.mountpoint_key.mount_id = get_mount_mount_id(syscall->mount.parent);
        syscall->mount.parent_mount_id_unique = get_mount_mount_id_unique(syscall->mount.parent);
        syscall->mount.mountpoint_key.ino = get_dentry_ino(syscall->mount.mountpoint_dentry);
        update_path_id(&syscall->mount.mountpoint_key, 0, 0);
    }

    // populate the device of the new mount
    syscall->mount.device = get_mount_dev(syscall->mount.newmnt);

    // populate the fs type of the new mount
    struct super_block *sb = get_dentry_sb(root_dentry);
    struct file_system_type *s_type = get_super_block_fs(sb);
    bpf_probe_read(&syscall->mount.fstype, sizeof(syscall->mount.fstype), &s_type->name);

    if (syscall->mount.root_key.mount_id == 0 || (!detached && syscall->mount.mountpoint_key.mount_id == 0) || syscall->mount.device == 0) {
        pop_syscall(syscall->type);
        return;
    }

    if(!detached) {
        syscall->resolver.key = syscall->mount.root_key;
        syscall->resolver.dentry = root_dentry;
        syscall->resolver.discarder_event_type = 0;
        syscall->resolver.callback = select_dr_key(prog_type, DR_MOUNT_STAGE_ONE_CALLBACK_KPROBE_KEY, DR_MOUNT_STAGE_ONE_CALLBACK_TRACEPOINT_KEY);
        syscall->resolver.iteration = 0;
        syscall->resolver.ret = 0;

        resolve_dentry(ctx, prog_type);

        // if the tail call fails, we need to pop the syscall cache entry
        pop_syscall(syscall->type);
    } else {
        send_detached_event(ctx, syscall);
    }
}

int __attribute__((always_inline)) dr_mount_stage_one_callback(void *ctx, enum TAIL_CALL_PROG_TYPE prog_type) {
    struct syscall_cache_t *syscall = peek_syscall_with(mountpoint_predicate);
    if (!syscall) {
        return 0;
    }

    syscall->resolver.key = syscall->mount.mountpoint_key;
    syscall->resolver.dentry = syscall->mount.mountpoint_dentry;
    syscall->resolver.discarder_event_type = 0;
    syscall->resolver.callback = select_dr_key(prog_type, DR_MOUNT_STAGE_TWO_CALLBACK_KPROBE_KEY, DR_MOUNT_STAGE_TWO_CALLBACK_TRACEPOINT_KEY);
    syscall->resolver.iteration = 0;
    syscall->resolver.ret = 0;

    resolve_dentry(ctx, prog_type);
    // if the tail call fails, we need to pop the syscall cache entry
    pop_syscall(syscall->type);

    return 0;
}

TAIL_CALL_FNC(dr_mount_stage_one_callback, ctx_t *ctx) {
    return dr_mount_stage_one_callback(ctx, KPROBE_OR_FENTRY_TYPE);
}

TAIL_CALL_TRACEPOINT_FNC(dr_mount_stage_one_callback, struct tracepoint_syscalls_sys_exit_t *args) {
    return dr_mount_stage_one_callback(args, TRACEPOINT_TYPE);
}

int __attribute__((always_inline)) dr_mount_stage_two_callback(void *ctx) {
    struct syscall_cache_t *syscall = peek_syscall_with(mountpoint_predicate);
    if (!syscall) {
        return 0;
    }

    if (syscall->type == EVENT_MOUNT || syscall->type == EVENT_OPEN_TREE || syscall->type == EVENT_MOVE_MOUNT) {
        struct mount_event_t event = {
            .syscall.retval = 0,
            .syscall_ctx.id = syscall->ctx_id,
            .source = SOURCE_OPEN_TREE,
            .mountfields.visible = false,
            .mountfields.detached = false,
        };

        fill_mount_fields(syscall, &event.mountfields);
        struct proc_cache_t *entry = fill_process_context(&event.process);
        fill_cgroup_context(entry, &event.cgroup);
        fill_span_context(&event.span);
        if (syscall->type != EVENT_OPEN_TREE) {
            // Only the first mount of a detached copy is detached from the VFS
            // All the other mounts are ultimately attached to the detached mount
            // That's why they aren't detached but are visible
            event.mountfields.visible = true;
            if(syscall->type == EVENT_MOUNT) {
                event.source = SOURCE_MOUNT;
            } else {
                event.source = SOURCE_MOVE_MOUNT;
            }
        }
        if (syscall->type == EVENT_MOVE_MOUNT) {
            send_event(ctx, EVENT_MOVE_MOUNT, event);
            return 0;
        }
        send_event(ctx, EVENT_MOUNT, event);
    } else if (syscall->type == EVENT_UNSHARE_MNTNS) {
        struct unshare_mntns_event_t event = { 0 };

        fill_mount_fields(syscall, &event.mountfields);
        send_event(ctx, EVENT_UNSHARE_MNTNS, event);
    }

    return 0;
}

TAIL_CALL_FNC(dr_mount_stage_two_callback, ctx_t *ctx) {
    return dr_mount_stage_two_callback(ctx);
}

TAIL_CALL_TRACEPOINT_FNC(dr_mount_stage_two_callback, struct tracepoint_syscalls_sys_exit_t *args) {
    return dr_mount_stage_two_callback(args);
}

HOOK_ENTRY("mnt_change_mountpoint")
int hook_mnt_change_mountpoint(ctx_t *ctx)
{
    bpf_printk("mnt_change_mountpoint");
    struct syscall_cache_t *syscall = peek_syscall(EVENT_MOVE_MOUNT);
    if(!syscall) {
        return 0;
    }

     struct mount *newmnt = (struct mount *)CTX_PARM3(ctx);
     if (syscall->mount.newmnt == newmnt) {
         return 0;
     }

     syscall->mount.newmnt = newmnt;
     syscall->mount.parent = (struct mount *)CTX_PARM1(ctx);
     struct mountpoint *mp = (struct mountpoint *)CTX_PARM2(ctx);
     syscall->mount.mountpoint_dentry = get_mountpoint_dentry(mp);

     handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, false);

    return 0;
}

HOOK_ENTRY("attach_mnt")
int hook_attach_mnt(ctx_t *ctx) {
    bpf_printk("attach_mnt");
    struct syscall_cache_t *syscall = peek_syscall_with(mountpoint_predicate);
    if (!syscall) {
        return 0;
    }

    struct mount *newmnt = (struct mount *)CTX_PARM1(ctx);
    // check if this mount has already been processed
    if (syscall->mount.newmnt == newmnt) {
        return 0;
    }

    if (syscall->type == EVENT_MOUNT) {
        if(syscall->mount.syscall_cache_id != -1) {
            mount_cache_add_mount_with_id(syscall->mount.syscall_cache_id, newmnt);
        }
        return 0;
    }

    syscall->mount.newmnt  = newmnt;
    syscall->mount.parent  = (struct mount *)CTX_PARM2(ctx);
    struct mountpoint *mp  = (struct mountpoint *)CTX_PARM3(ctx);
    syscall->mount.mountpoint_dentry = get_mountpoint_dentry(mp);
    if(syscall->mount.firstmount == NULL) {
        bpf_printk("First mount was null");
        syscall->mount.firstmount = newmnt;
        syscall->mount.firstmountparent = syscall->mount.parent;
    }
    handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, false);

    return 0;
}

HOOK_ENTRY("__attach_mnt")
int hook___attach_mnt(ctx_t *ctx) {
    bpf_printk("__attach_mnt");
    struct syscall_cache_t *syscall = peek_syscall_with(mountpoint_predicate);
    if (!syscall) {
        return 0;
    }

    struct mount *newmnt = (struct mount *)CTX_PARM1(ctx);
    struct mount *parent = (struct mount *)CTX_PARM2(ctx);

    // check if this mount has already been processed
    if (syscall->mount.newmnt == newmnt) {
        return 0;
    }

    if (syscall->type == EVENT_MOUNT) {
        if(syscall->mount.syscall_cache_id != -1) {
            mount_cache_add_mount_with_id(syscall->mount.syscall_cache_id, newmnt);
        }
        return 0;
    }

    u64 ns_inum = get_mount_mount_ns_inum(newmnt);
    if (!ns_inum) {
        ns_inum = get_mount_mount_ns_inum(parent);
    }
    syscall->mount.ns_inum = ns_inum;

    syscall->mount.newmnt  = newmnt;
    syscall->mount.parent  = (struct mount *)CTX_PARM2(ctx);
    syscall->mount.mountpoint_dentry = get_mount_mountpoint_dentry(newmnt);

    bpf_printk("__attach_mnt %lu", syscall->mount.ns_inum);
    handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, false);

    return 0;
}

HOOK_ENTRY("mnt_set_mountpoint")
int hook_mnt_set_mountpoint(ctx_t *ctx) {
    bpf_printk("mnt_set_mountpoint");

    struct syscall_cache_t *syscall = peek_syscall_with(unshare_or_move_mount);
    if (!syscall) {
        return 0;
    }

    struct mount *newmnt = (struct mount *)CTX_PARM3(ctx);
    // check if this mount has already been processed
    if (syscall->mount.newmnt == newmnt) {
        return 0;
    }
    syscall->mount.ns_inum = get_mount_mount_ns_inum((struct mount *)CTX_PARM1(ctx));

    syscall->mount.newmnt  = newmnt;
    syscall->mount.parent  = (struct mount *)CTX_PARM1(ctx);
    struct mountpoint *mp  = (struct mountpoint *)CTX_PARM2(ctx);
    syscall->mount.mountpoint_dentry = get_mountpoint_dentry(mp);

    handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, false);

    return 0;
}

HOOK_ENTRY("clone_mnt")
int hook_clone_mnt(ctx_t *ctx) {
    bpf_printk("clone_mnt entry");

    struct syscall_cache_t *syscall = peek_syscall_with(mount_or_open_tree);
    if (!syscall) {
        return 0;
    }

    if (syscall->type != EVENT_OPEN_TREE && (syscall->mount.bind_src_mount_id != 0 || syscall->mount.newmnt)) {
        return 0;
    }

    struct mount *bind_src_mnt = (struct mount *)CTX_PARM1(ctx);

    syscall->mount.bind_src_mount_id = get_mount_mount_id(bind_src_mnt);
    syscall->mount.bind_src_mount_id_unique = get_mount_mount_id_unique(bind_src_mnt);
    syscall->mount.clone_mnt_ctr++;

    return 0;
}

HOOK_EXIT("clone_mnt")
int rethook_clone_mnt(ctx_t *ctx) {
    bpf_printk("clone_mnt exit");
    struct syscall_cache_t *syscall = peek_syscall(EVENT_OPEN_TREE);

    if (!syscall) {
        return 0;
    }

    if(syscall->mount.clone_mnt_ctr != 1) {
        return 0;
    }

    struct mount *ret = (struct mount *)CTX_PARMRET(ctx);

    syscall->mount.newmnt = ret;
    handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, true);
    return 0;
}

HOOK_ENTRY("attach_recursive_mnt")
int hook_attach_recursive_mnt(ctx_t *ctx) {
    bpf_printk("attach_recursive_mnt");
    struct syscall_cache_t *syscall = peek_syscall_with(mount_or_move_mount);

    if (!syscall) {
        return 0;
    }

    struct mount *newmnt = (struct mount *)CTX_PARM1(ctx);
    // check if this mount has already been processed
    if (syscall->mount.newmnt == newmnt) {
        return 0;
    }

    syscall->mount.newmnt = newmnt;
    syscall->mount.parent = (struct mount *)CTX_PARM2(ctx);
    struct mountpoint *mp = (struct mountpoint *)CTX_PARM3(ctx);
    struct mount *topmnt = (struct mount *)CTX_PARM2(ctx);
    syscall->mount.ns_inum = get_mount_mount_ns_inum(topmnt);

    syscall->mount.mountpoint_dentry = get_mountpoint_dentry(mp);

    handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, false);
    return 0;
}

HOOK_ENTRY("propagate_mnt")
int hook_propagate_mnt(ctx_t *ctx) {
    bpf_printk("propagate_mnt");

    struct syscall_cache_t *syscall = peek_syscall_with(mount_or_move_mount);
    if (!syscall) {
        return 0;
    }

    struct mount *newmnt = (struct mount *)CTX_PARM3(ctx);
    // check if this mount has already been processed
    if (syscall->mount.newmnt == newmnt) {
        return 0;
    }

     syscall->mount.ns_inum = get_mount_mount_ns_inum((struct mount *)CTX_PARM1(ctx));
    bpf_printk("[OK] propagate_mnt inum = %lu", syscall->mount.ns_inum);

    syscall->mount.newmnt = newmnt;
    syscall->mount.parent = (struct mount *)CTX_PARM1(ctx);
    struct mountpoint *mp = (struct mountpoint *)CTX_PARM2(ctx);
    syscall->mount.mountpoint_dentry = get_mountpoint_dentry(mp);

    handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, false);

    return 0;
}

int __attribute__((always_inline)) sys_mount_ret(void *ctx, int retval, enum TAIL_CALL_PROG_TYPE prog_type) {
    if (retval) {
        pop_syscall(EVENT_MOUNT);
        return 0;
    }

    struct syscall_cache_t *syscall = peek_syscall(EVENT_MOUNT);
    if (!syscall) {
        return 0;
    }

    handle_new_mount(ctx, syscall, prog_type, false);
    pop_syscall(EVENT_MOUNT);
    return 0;
}

//HOOK_SYSCALL_COMPAT_EXIT(mount) {
//    struct syscall_cache_t *syscall = peek_syscall(EVENT_MOUNT);
//    if (!syscall) {
//        return 0;
//    }
//
//    struct mount_cache_t* cache = get_mount_cache_from_id(syscall->mount.syscall_cache_id);
//    if (cache != NULL) {
//        bpf_printk("found new mounts: %d", cache->cur_pos);
//        int i;
//
//        for(i = 0; i <= MOUNT_CACHE_SIZE; i++) {
//            if(i>cache->cur_pos) {
//                continue;
//            }
//
//            int id = get_mount_mount_id(cache->mounts[i]);
//            bpf_printk("mount found %d", id);
//        }
//    }
//
//    // process all the mountpoints here
//    if(syscall->mount.firstmount != NULL) {
//        syscall->mount.newmnt = syscall->mount.firstmount;
//        syscall->mount.parent = syscall->mount.firstmountparent;
//        handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, false);
//    }
//
//
//    int retval = SYSCALL_PARMRET(ctx);
//    return sys_mount_ret(ctx, retval, KPROBE_OR_FENTRY_TYPE);
//}

int __attribute__((always_inline)) mnt_ret(void *ctx, int retval, enum TAIL_CALL_PROG_TYPE prog_type) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_MOUNT);
    if (!syscall) {
        return 0;
    }

    struct mount_cache_t* cache = get_mount_cache_from_id(syscall->mount.syscall_cache_id);
    if (cache != NULL) {
        bpf_printk("found new mounts: %d", cache->cur_pos);
        int i;

        for(i = 0; i <= MOUNT_CACHE_SIZE; i++) {
            if(i>cache->cur_pos) {
                continue;
            }

            int id = get_mount_mount_id(cache->mounts[i]);
            bpf_printk("mount found %d", id);

        }
    }

    // process all the mountpoints here
    if(syscall->mount.firstmount != NULL) {
        syscall->mount.newmnt = syscall->mount.firstmount;
        syscall->mount.parent = syscall->mount.firstmountparent;
        handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, false);
    }


    //int retval = SYSCALL_PARMRET(ctx);
    return sys_mount_ret(ctx, retval, KPROBE_OR_FENTRY_TYPE);
}

#ifdef USE_SYSCALL_WRAPPER
  #ifdef USE_FENTRY
    #define MOUNT_X64_SEC "fexit/__x64_sys_mount"
  #else
    #define MOUNT_X64_SEC "kretprobe/__x64_sys_mount"
  #endif
#else
  #ifdef USE_FENTRY
    #define MOUNT_X64_SEC "fexit/sys_mount"
  #else
    #define MOUNT_X64_SEC "kretprobe/sys_mount"
  #endif
#endif

#define DEF_DUP_X64(i) \
SEC(MOUNT_X64_SEC) \
int rethook_mount_exit_dup_##i(ctx_t *ctx) { \
    bpf_printk("return!!"); \
    int retval = SYSCALL_PARMRET(ctx); \
    return mnt_ret(ctx, retval, KPROBE_OR_FENTRY_TYPE); \
}
REPEAT32(DEF_DUP_X64)

TAIL_CALL_TRACEPOINT_FNC(handle_sys_mount_exit, struct tracepoint_raw_syscalls_sys_exit_t *args) {
    return sys_mount_ret(args, args->ret, TRACEPOINT_TYPE);
}

HOOK_EXIT("alloc_vfsmnt")
int rethook_alloc_vfsmnt(ctx_t *ctx) {
    bpf_printk("alloc_vfsmnt exit");
    struct syscall_cache_t *syscall = peek_syscall(EVENT_FSMOUNT);
    if (!syscall) {
        return 0;
    }

    struct mount *newmnt = (struct mount *)CTX_PARMRET(ctx);
    syscall->mount.newmnt = newmnt;

    return 0;
}

HOOK_SYSCALL_ENTRY3(open_tree, int, dfd, const char *, filename, unsigned int, flags)
{
    bpf_printk("-> open_tree()");
    if (!(flags & OPEN_TREE_CLONE)) {
        return 0;
    }

    struct syscall_cache_t syscall = {
        .type = EVENT_OPEN_TREE,
    };
    cache_syscall(&syscall);
    return 0;
}

HOOK_SYSCALL_EXIT(open_tree) {
    bpf_printk("<- ret open_tree()");
    pop_syscall(EVENT_OPEN_TREE);
    return 0;
}

HOOK_SYSCALL_ENTRY3(fsmount, int, fs_fd, unsigned int, flags, unsigned int, attr_flags)
{
    bpf_printk("-> fsmount()");
    struct syscall_cache_t syscall = {
        .type = EVENT_FSMOUNT,
    };

    cache_syscall(&syscall);

    return 0;
}

HOOK_SYSCALL_EXIT(fsmount) {
    bpf_printk("<- ret fsmount()");
    struct syscall_cache_t *syscall = pop_syscall(EVENT_FSMOUNT);
    if (!syscall) {
        // should never happen
        return 0;
    }

    if(syscall->retval >= 0) {
        bpf_printk("fsmount");
        handle_new_mount(ctx, syscall, KPROBE_OR_FENTRY_TYPE, true);
    }

    return 0;
}

HOOK_SYSCALL_ENTRY4(move_mount, int, from_dfd, const char *, from_pathname, int, to_dfd, const char *, to_pathname)
{
    bpf_printk("-> move_mount()");
    struct syscall_cache_t syscall = {
        .type = EVENT_MOVE_MOUNT,
    };

    cache_syscall(&syscall);

    return 0;
}


HOOK_SYSCALL_EXIT(move_mount) {
    bpf_printk("<- ret move_mount()");
    struct syscall_cache_t *syscall = pop_syscall(EVENT_MOVE_MOUNT);
    if (!syscall) {
        // should never happen
        return 0;
    }

    return 0;
}

int __attribute__((always_inline)) multi_mount_stage_one(void *ctx, enum TAIL_CALL_PROG_TYPE prog_type) {
    struct syscall_cache_t *syscall = peek_syscall_with(mountpoint_predicate);
    if (!syscall) {
        return 0;
    }

    syscall->resolver.key = syscall->mount.mountpoint_key;
    syscall->resolver.dentry = syscall->mount.mountpoint_dentry;
    syscall->resolver.discarder_event_type = 0;
    syscall->resolver.callback = select_dr_key(prog_type, DR_MOUNT_STAGE_TWO_CALLBACK_KPROBE_KEY, DR_MOUNT_STAGE_TWO_CALLBACK_TRACEPOINT_KEY);
    syscall->resolver.iteration = 0;
    syscall->resolver.ret = 0;

    resolve_dentry(ctx, prog_type);
    // if the tail call fails, we need to pop the syscall cache entry
    pop_syscall(syscall->type);

    return 0;
}

#endif
