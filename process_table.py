from process_info import ProcessInfo
from bpf_collector import BpfSample
import os

class ProcTable:

    def __init__(self):
        self.proc_table = {}
        self.PROC_FOLDER_PATH="/proc"

    def add_process(self, proc_info):
        self.proc_table[proc_info.get_pid()] = proc_info

    def add_process_from_sample(self, sample):
        for key, value in sample.get_pid_dict().iteritems():
            if key in self.proc_table:
                # process already there, check if comm is the same
                if value.get_comm() == self.proc_table[key].get_comm():
                    # ok, update stuff
                    self.proc_table[key].set_power(value.get_power())
                    self.proc_table[key].set_socket_data_array(\
                        value.get_socket_data())

                else:
                    # process is changed, replace entry and find cgroup_id
                    value.set_cgroup_id(self.find_cgroup_id(key))
                    if value.get_cgroup_id() != "":
                        value.set_container_id(value.get_cgroup_id()[0:12])
                    self.proc_table[key] = value
            else:
                # new process, add it and find cgroup_id
                value.set_cgroup_id(self.find_cgroup_id(key))
                if value.get_cgroup_id() != "":
                    value.set_container_id(value.get_cgroup_id()[0:12])
                self.proc_table[key] = value

    def find_cgroup_id(self, pid):
        #scan proc folder searching for the pid
        try:
            with open(os.path.join('/proc', str(pid), 'cgroup'), 'rb') as f:
                for line in f:
                    line_array = line.split("/")
                    if len(line_array) > 1 and len(line_array[len(line_array) -1]) == 65:
                        return line_array[len(line_array) -1]
        except IOError: # proc has already terminated
            return ""
        return ""
