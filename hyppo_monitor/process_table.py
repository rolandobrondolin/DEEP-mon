from process_info import ProcessInfo
from bpf_collector import BpfSample
from container_info import ContainerInfo
import os

class ProcTable:

    def __init__(self):
        self.proc_table = {}

    def add_process(self, proc_info):
        self.proc_table[proc_info.get_pid()] = proc_info

    def add_process_from_sample(self, sample):
        # reset counters for each entries

        evicted_keys = []

        for proc_table_key, proc_table_value in self.proc_table.iteritems():
            if proc_table_value.get_last_ts() + 8000000000 < sample.get_max_ts():
                evicted_keys.append(proc_table_key)
            else:
                proc_table_value.set_power(0)
                proc_table_value.set_cpu_usage(0)
                proc_table_value.reset_data()

        #remove evicted keys
        for k in evicted_keys:
            self.proc_table.pop(k, None)

        for key, value in sample.get_pid_dict().iteritems():
            if key in self.proc_table:
                # process already there, check if comm is the same
                if value.get_comm() == self.proc_table[key].get_comm():
                    # ok, update stuff
                    self.proc_table[key].set_power(value.get_power())
                    self.proc_table[key].set_cpu_usage(value.get_cpu_usage())
                    self.proc_table[key].set_instruction_retired(value.get_instruction_retired())
                    self.proc_table[key].set_cycles(value.get_cycles())
                    self.proc_table[key].set_cache_misses(value.get_cache_misses())
                    self.proc_table[key].set_cache_refs(value.get_cache_refs())
                    self.proc_table[key].set_time_ns(value.get_time_ns())
                    self.proc_table[key].set_socket_data_array(\
                        value.get_socket_data())

                else:
                    # process is changed, replace entry and find cgroup_id
                    value.set_cgroup_id(self.find_cgroup_id(key, value.tgid))
                    value.set_container_id(value.get_cgroup_id()[0:12])
                    self.proc_table[key] = value
            else:
                # new process, add it and find cgroup_id
                value.set_cgroup_id(self.find_cgroup_id(key, value.tgid))
                value.set_container_id(value.get_cgroup_id()[0:12])
                self.proc_table[key] = value

    def find_cgroup_id(self, pid, tgid):
        # exclude idle
        if pid < 0:
            return "----idle----"

        for id in [pid, tgid]:

            #scan proc folder searching for the pid
            for path in ['/host/proc', '/proc']:
                try:
                    # Non-systemd Docker
                    with open(os.path.join(path, str(id), 'cgroup'), 'rb') as f:
                        for line in f:
                            line_array = line.split("/")
                            if len(line_array) > 1 and \
                                len(line_array[len(line_array) -1]) == 65:
                                return line_array[len(line_array) -1]
                except IOError:
                    continue

            for path in ['/host/proc', '/proc']:
                try:
                    # systemd Docker
                    with open(os.path.join(path, str(id), 'cgroup'), 'rb') as f:
                        for line in f:
                            line_array = line.split("/")
                            if len(line_array) > 1 \
                                and "docker-" in line_array[len(line_array) -1] \
                                and ".scope" in line_array[len(line_array) -1]:

                                new_id = line_array[len(line_array) -1].replace("docker-", "")
                                new_id = new_id.replace(".scope", "")
                                if len(new_id) == 65:
                                    return new_id

                except IOError: # proc has already terminated
                    continue
        return "---others---"

    def get_proc_table(self):
        return self.proc_table

    def get_container_dictionary(self):
        container_dict = {}
        # not_a_container = ContainerInfo("---others---")
        # idle = ContainerInfo("----idle----")
        # container_dict["---others---"] = not_a_container
        # container_dict["----idle----"] = idle

        for key, value in self.proc_table.iteritems():
            if value.container_id != "":
                if value.container_id not in container_dict:
                    container_dict[value.container_id] = ContainerInfo(value.container_id)
                container_dict[value.container_id].add_cycles(value.get_cycles())
                container_dict[value.container_id].add_weighted_cycles(value.get_aggregated_weighted_cycles())
                container_dict[value.container_id].add_instructions(value.get_instruction_retired())
                container_dict[value.container_id].add_cache_misses(value.get_cache_misses())
                container_dict[value.container_id].add_cache_refs(value.get_cache_refs())
                container_dict[value.container_id].add_time_ns(value.get_time_ns())
                container_dict[value.container_id].add_power(value.get_power())
                container_dict[value.container_id].add_cpu_usage(value.get_cpu_usage())
                container_dict[value.container_id].add_pid(value.get_pid())
                container_dict[value.container_id].set_last_ts(value.get_last_ts())


        return container_dict
