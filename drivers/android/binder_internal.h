/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_BINDER_INTERNAL_H
#define _LINUX_BINDER_INTERNAL_H

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <uapi/linux/android/binder.h>
#include <uapi/linux/sched/types.h>

#include "binder_alloc.h"

struct binder_context {
	struct binder_node *binder_context_mgr_node;
	struct mutex context_mgr_node_lock;
	kuid_t binder_context_mgr_uid;
	const char *name;
};

/**
 * struct binder_device - information about a binder device node
 * @hlist:          list of binder devices (only used for devices requested via
 *                  CONFIG_ANDROID_BINDER_DEVICES)
 * @miscdev:        information about a binder character device node
 * @context:        binder context information
 * @binderfs_inode: This is the inode of the root dentry of the super block
 *                  belonging to a binderfs mount.
 */
struct binder_device {
	struct hlist_node hlist;
	struct miscdevice miscdev;
	struct binder_context context;
	struct inode *binderfs_inode;
	refcount_t ref;
};

/**
 * binderfs_mount_opts - mount options for binderfs
 * @max: maximum number of allocatable binderfs binder devices
 * @stats_mode: enable binder stats in binderfs.
 */
struct binderfs_mount_opts {
	int max;
	int stats_mode;
};

/**
 * binderfs_info - information about a binderfs mount
 * @ipc_ns:         The ipc namespace the binderfs mount belongs to.
 * @control_dentry: This records the dentry of this binderfs mount
 *                  binder-control device.
 * @root_uid:       uid that needs to be used when a new binder device is
 *                  created.
 * @root_gid:       gid that needs to be used when a new binder device is
 *                  created.
 * @mount_opts:     The mount options in use.
 * @device_count:   The current number of allocated binder devices.
 * @proc_log_dir:   Pointer to the directory dentry containing process-specific
 *                  logs.
 * @proc_transaction_log_dir:   Pointer to the directory dentry containing miui binder
 *                  logs.
 */
struct binderfs_info {
	struct ipc_namespace *ipc_ns;
	struct dentry *control_dentry;
	kuid_t root_uid;
	kgid_t root_gid;
	struct binderfs_mount_opts mount_opts;
	int device_count;
	struct dentry *proc_log_dir;
	//MIUI ADD:
	struct dentry *proc_transaction_log_dir;
	//END
};

extern const struct file_operations binder_fops;

extern char *binder_devices_param;

#ifdef CONFIG_ANDROID_BINDERFS
extern bool is_binderfs_device(const struct inode *inode);
extern struct dentry *binderfs_create_file(struct dentry *dir, const char *name,
					   const struct file_operations *fops,
					   void *data);
extern void binderfs_remove_file(struct dentry *dentry);
#else
static inline bool is_binderfs_device(const struct inode *inode)
{
	return false;
}
static inline struct dentry *binderfs_create_file(struct dentry *dir,
					   const char *name,
					   const struct file_operations *fops,
					   void *data)
{
	return NULL;
}
static inline void binderfs_remove_file(struct dentry *dentry) {}
#endif

#ifdef CONFIG_ANDROID_BINDERFS
extern int __init init_binderfs(void);
#else
static inline int __init init_binderfs(void)
{
	return 0;
}
#endif

int binder_stats_show(struct seq_file *m, void *unused);
DEFINE_SHOW_ATTRIBUTE(binder_stats);

int binder_state_show(struct seq_file *m, void *unused);
DEFINE_SHOW_ATTRIBUTE(binder_state);

int binder_transactions_show(struct seq_file *m, void *unused);
DEFINE_SHOW_ATTRIBUTE(binder_transactions);

int binder_transaction_log_show(struct seq_file *m, void *unused);
DEFINE_SHOW_ATTRIBUTE(binder_transaction_log);

struct binder_transaction_log_entry {
	int debug_id;
	int debug_id_done;
	int call_type;
	int from_proc;
	int from_thread;
	int target_handle;
	int to_proc;
	int to_thread;
	int to_node;
	int data_size;
	int offsets_size;
	int return_error_line;
	uint32_t return_error;
	uint32_t return_error_param;
	char context_name[BINDERFS_MAX_NAME + 1];
};

struct binder_transaction_log {
	atomic_t cur;
	bool full;
	struct binder_transaction_log_entry entry[32];
};

extern struct binder_transaction_log binder_transaction_log;
extern struct binder_transaction_log binder_transaction_log_failed;

enum binder_stat_types {
	BINDER_STAT_PROC,
	BINDER_STAT_THREAD,
	BINDER_STAT_NODE,
	BINDER_STAT_REF,
	BINDER_STAT_DEATH,
	BINDER_STAT_TRANSACTION,
	BINDER_STAT_TRANSACTION_COMPLETE,
	BINDER_STAT_COUNT
};

struct binder_stats {
	atomic_t br[_IOC_NR(BR_FAILED_REPLY) + 1];
	atomic_t bc[_IOC_NR(BC_REPLY_SG) + 1];
	atomic_t obj_created[BINDER_STAT_COUNT];
	atomic_t obj_deleted[BINDER_STAT_COUNT];
};

/**
 * struct binder_work - work enqueued on a worklist
 * @entry:             node enqueued on list
 * @type:              type of work to be performed
 *
 * There are separate work lists for proc, thread, and node (async).
 */
struct binder_work {
	struct list_head entry;

	enum binder_work_type {
		BINDER_WORK_TRANSACTION = 1,
		BINDER_WORK_TRANSACTION_COMPLETE,
		BINDER_WORK_RETURN_ERROR,
		BINDER_WORK_NODE,
		BINDER_WORK_DEAD_BINDER,
		BINDER_WORK_DEAD_BINDER_AND_CLEAR,
		BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
	} type;
};

struct binder_error {
	struct binder_work work;
	uint32_t cmd;
};

/**
 * struct binder_node - binder node bookkeeping
 * @debug_id:             unique ID for debugging
 *                        (invariant after initialized)
 * @lock:                 lock for node fields
 * @work:                 worklist element for node work
 *                        (protected by @proc->inner_lock)
 * @rb_node:              element for proc->nodes tree
 *                        (protected by @proc->inner_lock)
 * @dead_node:            element for binder_dead_nodes list
 *                        (protected by binder_dead_nodes_lock)
 * @proc:                 binder_proc that owns this node
 *                        (invariant after initialized)
 * @refs:                 list of references on this node
 *                        (protected by @lock)
 * @internal_strong_refs: used to take strong references when
 *                        initiating a transaction
 *                        (protected by @proc->inner_lock if @proc
 *                        and by @lock)
 * @local_weak_refs:      weak user refs from local process
 *                        (protected by @proc->inner_lock if @proc
 *                        and by @lock)
 * @local_strong_refs:    strong user refs from local process
 *                        (protected by @proc->inner_lock if @proc
 *                        and by @lock)
 * @tmp_refs:             temporary kernel refs
 *                        (protected by @proc->inner_lock while @proc
 *                        is valid, and by binder_dead_nodes_lock
 *                        if @proc is NULL. During inc/dec and node release
 *                        it is also protected by @lock to provide safety
 *                        as the node dies and @proc becomes NULL)
 * @ptr:                  userspace pointer for node
 *                        (invariant, no lock needed)
 * @cookie:               userspace cookie for node
 *                        (invariant, no lock needed)
 * @has_strong_ref:       userspace notified of strong ref
 *                        (protected by @proc->inner_lock if @proc
 *                        and by @lock)
 * @pending_strong_ref:   userspace has acked notification of strong ref
 *                        (protected by @proc->inner_lock if @proc
 *                        and by @lock)
 * @has_weak_ref:         userspace notified of weak ref
 *                        (protected by @proc->inner_lock if @proc
 *                        and by @lock)
 * @pending_weak_ref:     userspace has acked notification of weak ref
 *                        (protected by @proc->inner_lock if @proc
 *                        and by @lock)
 * @has_async_transaction: async transaction to node in progress
 *                        (protected by @lock)
 * @sched_policy:         minimum scheduling policy for node
 *                        (invariant after initialized)
 * @accept_fds:           file descriptor operations supported for node
 *                        (invariant after initialized)
 * @min_priority:         minimum scheduling priority
 *                        (invariant after initialized)
 * @inherit_rt:           inherit RT scheduling policy from caller
 * @txn_security_ctx:     require sender's security context
 *                        (invariant after initialized)
 * @async_todo:           list of async work items
 *                        (protected by @proc->inner_lock)
 *
 * Bookkeeping structure for binder nodes.
 */
struct binder_node {
	int debug_id;
	spinlock_t lock;
	struct binder_work work;
	union {
		struct rb_node rb_node;
		struct hlist_node dead_node;
	};
	struct binder_proc *proc;
	struct hlist_head refs;
	int internal_strong_refs;
	int local_weak_refs;
	int local_strong_refs;
	int tmp_refs;
	binder_uintptr_t ptr;
	binder_uintptr_t cookie;
	struct {
		/*
		 * bitfield elements protected by
		 * proc inner_lock
		 */
		u8 has_strong_ref:1;
		u8 pending_strong_ref:1;
		u8 has_weak_ref:1;
		u8 pending_weak_ref:1;
	};
	struct {
		/*
		 * invariant after initialization
		 */
		u8 sched_policy:2;
		u8 inherit_rt:1;
		u8 accept_fds:1;
		u8 txn_security_ctx:1;
		u8 min_priority;
	};
	bool has_async_transaction;
	struct list_head async_todo;
};

struct binder_ref_death {
	/**
	 * @work: worklist element for death notifications
	 *        (protected by inner_lock of the proc that
	 *        this ref belongs to)
	 */
	struct binder_work work;
	binder_uintptr_t cookie;
};

/**
 * struct binder_ref_data - binder_ref counts and id
 * @debug_id:        unique ID for the ref
 * @desc:            unique userspace handle for ref
 * @strong:          strong ref count (debugging only if not locked)
 * @weak:            weak ref count (debugging only if not locked)
 *
 * Structure to hold ref count and ref id information. Since
 * the actual ref can only be accessed with a lock, this structure
 * is used to return information about the ref to callers of
 * ref inc/dec functions.
 */
struct binder_ref_data {
	int debug_id;
	uint32_t desc;
	int strong;
	int weak;
};

/**
 * struct binder_ref - struct to track references on nodes
 * @data:        binder_ref_data containing id, handle, and current refcounts
 * @rb_node_desc: node for lookup by @data.desc in proc's rb_tree
 * @rb_node_node: node for lookup by @node in proc's rb_tree
 * @node_entry:  list entry for node->refs list in target node
 *               (protected by @node->lock)
 * @proc:        binder_proc containing ref
 * @node:        binder_node of target node. When cleaning up a
 *               ref for deletion in binder_cleanup_ref, a non-NULL
 *               @node indicates the node must be freed
 * @death:       pointer to death notification (ref_death) if requested
 *               (protected by @node->lock)
 *
 * Structure to track references from procA to target node (on procB). This
 * structure is unsafe to access without holding @proc->outer_lock.
 */
struct binder_ref {
	/* Lookups needed: */
	/*   node + proc => ref (transaction) */
	/*   desc + proc => ref (transaction, inc/dec ref) */
	/*   node => refs + procs (proc exit) */
	struct binder_ref_data data;
	struct rb_node rb_node_desc;
	struct rb_node rb_node_node;
	struct hlist_node node_entry;
	struct binder_proc *proc;
	struct binder_node *node;
	struct binder_ref_death *death;
};

#endif /* _LINUX_BINDER_INTERNAL_H */
