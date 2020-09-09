#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/dcache.h>
#include <linux/mount.h>

struct val_t {
    u32 sz;
    u64 ts;
    u32 name_len;
    char name[DNAME_INLINE_LEN];
    char parent1[DNAME_INLINE_LEN];
    char parent2[DNAME_INLINE_LEN];
};

struct val_pid_t {
    u32 pid;
    u64 num_r;
    u64 num_w;
    u64 bytes_r;
    u64 bytes_w;
    u64 sum_ts_deltas;
};

struct val_file_t {
    u64 num_r;
    u64 num_w;
    u64 bytes_r;
    u64 bytes_w;
};

struct key_file_t {
    char name[DNAME_INLINE_LEN];
    char parent1[DNAME_INLINE_LEN];
    char parent2[DNAME_INLINE_LEN];
};


BPF_HASH(counts_by_pid, pid_t, struct val_pid_t);
BPF_HASH(counts_by_file, struct key_file_t, struct val_file_t);
BPF_HASH(entryinfo, pid_t, struct val_t);

int trace_rw_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 pid = bpf_get_current_pid_tgid();
    int mode = file->f_inode->i_mode;
    struct dentry *de = file->f_path.dentry;
    if (de->d_name.len == 0 || !S_ISREG(mode))
        return 0;
    // store size and timestamp by pid
    struct val_t val = {};
    val.sz = count;
    val.ts = bpf_ktime_get_ns();
    struct qstr d_name = de->d_name;
    val.name_len = d_name.len;

    bpf_probe_read(&val.name, sizeof(val.name), d_name.name);

    struct dentry *parent = de->d_parent;
    if (parent) {
        struct qstr parent_name = parent->d_name;
        bpf_probe_read(&val.parent1, sizeof(val.parent1), parent_name.name);

        struct dentry *second_parent = parent->d_parent;

        struct qstr second_parent_name = second_parent->d_name;
        bpf_probe_read(&val.parent2, sizeof(val.parent2), second_parent_name.name);
    }

    entryinfo.update(&pid, &val);
    return 0;
}

static int trace_rw_return(struct pt_regs *ctx, int type) {
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();

    //searches for key value and discards request if not found
    valp = entryinfo.lookup(&pid);
    if (valp == 0) {
        return 0;
    }

    //calculates delta and removes key
    u64 delta_us = (bpf_ktime_get_ns() - valp->ts) / 1000;
    entryinfo.delete(&pid);

    struct val_pid_t *val_pid, zero_pid = {};
    val_pid = counts_by_pid.lookup_or_init(&pid, &zero_pid);
    if (val_pid) {
        if (type == 0) {
            val_pid->num_r++;
            val_pid->bytes_r += valp->sz;
        } else {
            val_pid->num_w++;
            val_pid->bytes_w += valp->sz;
        }
        val_pid->sum_ts_deltas += delta_us;
        val_pid->pid = pid;
    }

    struct key_file_t file_key = {};
    bpf_probe_read(&file_key.name, sizeof(file_key.name), valp->name);
    bpf_probe_read(&file_key.parent1, sizeof(file_key.parent1), valp->parent1);
    bpf_probe_read(&file_key.parent2, sizeof(file_key.parent2), valp->parent2);

    struct val_file_t *val_file, zero_file = {};
    val_file = counts_by_file.lookup_or_init(&file_key, &zero_file);

    if (val_file) {
        if (type == 0) {
            val_file->num_r++;
            val_file->bytes_r += valp->sz;
        } else {
            val_file->num_w++;
            val_file->bytes_w += valp->sz;
        }
    }
    return 0;
}

int trace_read_return(struct pt_regs *ctx) {
    return trace_rw_return(ctx, 0);
}
int trace_write_return(struct pt_regs *ctx) {
    return trace_rw_return(ctx, 1);
}
