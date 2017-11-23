from process_info import ProcessInfo
from bpf_collector import BpfSample
from container_info import ContainerInfo
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
                    if len(line_array) > 1 and \
                        len(line_array[len(line_array) -1]) == 65:
                        return line_array[len(line_array) -1]
        except IOError: # proc has already terminated
            return ""
        return ""

    def get_container_dictionary(self):
        container_dict = {}
        not_a_container = ContainerInfo("---others---")
        idle = ContainerInfo("----idle----")
        container_dict["---others---"] = not_a_container
        container_dict["----idle----"] = idle

        for key, value in self.proc_table.iteritems():
            if value.container_id != "":
                if value.container_id not in container_dict:
                    container_dict[value.container_id] = ContainerInfo(\
                        value.container_id)
                container_dict[value.container_id].add_weighted_cycles(\
                    value.get_aggregated_weighted_cycles())
                container_dict[value.container_id].add_time_ns(\
                    value.get_aggregated_time_ns())
                container_dict[value.container_id].add_power(\
                    value.get_power())
                container_dict[value.container_id].add_pid(value.get_pid())
            elif key > 0:
                not_a_container.add_weighted_cycles(\
                    value.get_aggregated_weighted_cycles())
                not_a_container.add_time_ns(value.get_aggregated_time_ns())
                not_a_container.add_power(value.get_power())
                not_a_container.add_pid(value.get_pid())
            else:
                idle.add_weighted_cycles(\
                    value.get_aggregated_weighted_cycles())
                idle.add_time_ns(value.get_aggregated_time_ns())
                idle.add_power(value.get_power())
                idle.add_pid(value.get_pid())


        return container_dict
