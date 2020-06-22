from __future__ import print_function
from bcc import BPF
import os
import snap_plugin.v1 as snap
import json

prog = """
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
"""

class DiskCollector:
    def __init__(self, monitor_disk, monitor_file):
        self.monitor_file = monitor_file
        self.monitor_disk = monitor_disk
        self.disk_sample = None
        self.disk_monitor = None
        self.proc_path = "/host/proc"
        self.proc_files = [f for f in os.listdir(self.proc_path) if os.path.isfile(os.path.join(self.proc_path, f))]
        self.number_files_to_keep = 10

    def start_capture(self):
        global prog
        DNAME_INLINE_LEN = 32  # linux/dcache.h
        self.disk_monitor = BPF(text=prog)
        self.disk_monitor.attach_kprobe(event="vfs_read", fn_name="trace_rw_entry")
        self.disk_monitor.attach_kretprobe(event="vfs_read", fn_name="trace_read_return")

        self.disk_monitor.attach_kprobe(event="vfs_write", fn_name="trace_rw_entry")
        self.disk_monitor.attach_kretprobe(event="vfs_write", fn_name="trace_write_return")

    def _include_file_path(self, file_name, file_parent, file_parent2):
        if (file_parent == "/"):
            if (file_name in self.proc_files or file_name.isdigit()):
                return False
            return "/"+file_name
        if (file_parent2 == "/"):
            if (file_parent in self.proc_files or file_parent.isdigit()):
                return False
            return "/"+file_parent+"/"+file_name
        if (file_parent2 in self.proc_files or file_parent2.isdigit()):
            return False
        return file_parent2+"/"+file_parent+"/"+file_name

    def get_sample(self):
        disk_dict = {}
        if (self.monitor_disk):
            disk_counts = self.disk_monitor["counts_by_pid"]
            for k,v in disk_counts.items():
                key = int(v.pid)
                disk_dict[key] = {}
                disk_dict[key]["kb_r"] = int(v.bytes_r/1000)
                disk_dict[key]["kb_w"] = int(v.bytes_w/1000)
                disk_dict[key]["num_r"] = int(v.num_r)
                disk_dict[key]["num_w"] = int(v.num_w)
                disk_dict[key]["avg_lat"] = float(v.sum_ts_deltas) / 1000 / (v.num_r+v.num_w)
                disk_dict[key]["container_ID"] = "---others---"
                if (os.path.exists(os.path.join(self.proc_path,str(v.pid),"cgroup"))):
                    try:
                        with open(os.path.join(self.proc_path, str(v.pid), 'cgroup'), 'rb') as f:
                            for line in f:
                                line_array = line.split("/")
                                if len(line_array) > 1 and \
                                    len(line_array[len(line_array) -1]) == 65:
                                    disk_dict[key]["container_ID"] = line_array[len(line_array) -1][:-1]
                                    break
                    except IOError:
                        continue
                    # systemd Docker
                    try:
                        with open(os.path.join(self.proc_path, str(v.pid), 'cgroup'), 'rb') as f:
                            for line in f:
                                line_array = line.split("/")
                                if len(line_array) > 1 \
                                    and "docker-" in line_array[len(line_array) -1] \
                                    and ".scope" in line_array[len(line_array) -1]:

                                    new_id = line_array[len(line_array) -1].replace("docker-", "")
                                    new_id = new_id.replace(".scope", "")
                                    if len(new_id) == 65:
                                        disk_dict[key]["container_ID"] = new_id
                                        break
                    except IOError:
                        continue

            disk_dict =  self._aggregate_metrics_by_container(disk_dict)
            disk_counts.clear()
        
        file_dict = {}
        if (self.monitor_file):
            counter = 0
            file_counts = self.disk_monitor.get_table("counts_by_file")
            for k, v in reversed(sorted(file_counts.items(), key=lambda counts_f: (counts_f[1].bytes_r+counts_f[1].bytes_w))):
                if (self._include_file_path(k.name, k.parent1, k.parent2) != False) and counter < self.number_files_to_keep:
                    key = self._include_file_path(k.name, k.parent1, k.parent2)
                    file_dict[key] = FileInfo()
                    file_dict[key].set_file_path(key)
                    file_dict[key].set_kb_r(int(v.bytes_r/1000))
                    file_dict[key].set_kb_w(int(v.bytes_w/1000))
                    file_dict[key].set_num_r(int(v.num_r))
                    file_dict[key].set_num_w(int(v.num_w))
                file_dict[key].set_file_id(counter)
                counter+=1

            file_counts.clear()


        aggregate_dict = {}
        aggregate_dict['file_sample'] = file_dict
        aggregate_dict['disk_sample'] = disk_dict
        return aggregate_dict

    def _aggregate_metrics_by_container(self, disk_sample):
        container_dict = dict()
        for pid in disk_sample:
            shortened_ID = disk_sample[pid]["container_ID"][:12]
            if shortened_ID not in container_dict:
                container_dict[shortened_ID] = {}
                container_dict[shortened_ID]["full_ID"] = disk_sample[pid]["container_ID"]
                container_dict[shortened_ID]["kb_r"] = 0
                container_dict[shortened_ID]["kb_w"] = 0
                container_dict[shortened_ID]["num_r"] = 0
                container_dict[shortened_ID]["num_w"] = 0
                container_dict[shortened_ID]["avg_lat"] = 0
                container_dict[shortened_ID]["pids"] = []
            container_dict[shortened_ID]["kb_r"] += disk_sample[pid]["kb_r"]
            container_dict[shortened_ID]["kb_w"] += disk_sample[pid]["kb_w"]
            container_dict[shortened_ID]["num_r"] += disk_sample[pid]["num_r"]
            container_dict[shortened_ID]["num_w"] += disk_sample[pid]["num_w"]
            container_dict[shortened_ID]["num_w"] += disk_sample[pid]["num_w"]
            container_dict[shortened_ID]["avg_lat"] += disk_sample[pid]["avg_lat"]
            container_dict[shortened_ID]["pids"].append(pid)
        for k,v in container_dict:
            container_dict[k]["avg_lat"] = container_dict[k]["avg_lat"] /  len(container_dict[k]["pids"])

        return container_dict 



class FileInfo:
    def __init__(self):
        self.file_path = ""
        self.kb_r = 0
        self.kb_w = 0
        self.num_r = 0
        self.num_w = 0
        self.file_id = 0

    def get_file_path(self):
        return self.file_path

    def get_kb_r(self):
        return self.kb_r

    def get_kb_w(self):
        return self.kb_w

    def get_num_r(self):
        return self.num_r

    def get_num_w(self):
        return self.num_w

    def get_file_id(self):
        return self.file_id

    def set_file_id(self, file_id):
        self.file_id = file_id

    def set_file_path(self, file_path):
        self.file_path = file_path
    
    def set_kb_r(self, kbr):
        self.kb_r = kbr

    def set_kb_w(self, kbw):
        self.kb_w = kbw

    def set_num_r(self, numr):
        self.num_r = numr

    def set_num_w(self, numw):
        self.num_w = numw

    def _get_file_summary(self, request_time, snap_namespace):
        file_summary = {
            "file_kb_r": {"value": self.get_kb_r(), "strategy": "sum", "type": "int64"},
            "file_kb_w": {"value": self.get_kb_w(), "strategy": "sum", "type": "int64"},
            "file_num_r": {"value": self.get_num_r(), "strategy": "sum", "type": "int64"},
            "file_num_w": {"value": self.get_num_w(), "strategy": "sum", "type": "int64"},
        }
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="File summary",
            data=json.dumps(file_summary),
            timestamp=request_time
        )
        return metric

    def to_snap(self, request_time, user_id, hostname):
        metrics_to_be_returned = []

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value=user_id),
            snap.NamespaceElement(value=hostname),
            snap.NamespaceElement(value="file"),
            snap.NamespaceElement(value=str(self.file_path)),
	    snap.NamespaceElement(value=str(self.file_id)),
            snap.NamespaceElement(value="file_summary")
        ]
        metrics_to_be_returned.append(self._get_file_summary(request_time, namespace))
        return metrics_to_be_returned
    
