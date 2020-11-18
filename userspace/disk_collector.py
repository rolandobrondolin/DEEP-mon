"""
    DEEP-mon
    Copyright (C) 2020  Brondolin Rolando

    This file is part of DEEP-mon

    DEEP-mon is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DEEP-mon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from bcc import BPF
import os
import json

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
        bpf_code_path = os.path.dirname(os.path.abspath(__file__)) \
                        + "/../bpf/vfs_monitor.c"
        #DNAME_INLINE_LEN = 32  # linux/dcache.h
        self.disk_monitor = BPF(src_file=bpf_code_path, cflags=["-DNAME_INLINE_LEN=%d" % 32])
        self.disk_monitor.attach_kprobe(event="vfs_read", fn_name="trace_rw_entry")
        self.disk_monitor.attach_kretprobe(event="vfs_read", fn_name="trace_read_return")

        self.disk_monitor.attach_kprobe(event="vfs_write", fn_name="trace_rw_entry")
        self.disk_monitor.attach_kretprobe(event="vfs_write", fn_name="trace_write_return")

    def _include_file_path(self, file_name, file_parent, file_parent2):
        file_name = file_name.decode("utf-8")
        file_parent = file_parent.decode("utf-8")
        file_parent2 = file_parent2.decode("utf-8")

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
                        with open(os.path.join(self.proc_path, str(v.pid), 'cgroup'), 'r') as f:
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
                        with open(os.path.join(self.proc_path, str(v.pid), 'cgroup'), 'r') as f:
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
        for k,v in container_dict.items():
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
