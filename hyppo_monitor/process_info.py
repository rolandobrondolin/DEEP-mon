import ctypes as ct
import snap_plugin.v1 as snap

class BpfPidStatus(ct.Structure):
    TASK_COMM_LEN = 16
    socket_size = 0
    _fields_ = [("pid", ct.c_int),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("weighted_cycles", ct.c_ulonglong * 2 * socket_size),
                ("instruction_retired", ct.c_ulonglong * 2 * socket_size),
                ("time_ns", ct.c_ulonglong * 2 * socket_size),
                ("bpf_selector", ct.c_int),
                ("ts", ct.c_ulonglong * 2 * socket_size)]

    def __init__(self, socket_size):
        self.socket_size = socket_size

class SocketProcessItem:

    def __init__(self, weighted_cycles = 0, instruction_retired = 0, time_ns = 0, ts = 0):
        self.instruction_retired = instruction_retired
        self.weighted_cycles = weighted_cycles
        self.time_ns = time_ns
        self.ts = ts

    def set_weighted_cycles(self, weighted_cycles):
        self.weighted_cycles = weighted_cycles

    def set_instruction_retired(self, instruction_retired):
        self.instruction_retired = instruction_retired

    def set_time_ns(self, time_ns):
        self.time_ns = time_ns

    def set_ts(self, ts):
        self.ts = ts

    def get_weighted_cycles(self):
        return self.weighted_cycles

    def get_instruction_retired(self):
        return self.instruction_retired

    def get_time_ns(self):
        return self.time_ns

    def get_ts(self):
        return self.ts

    def reset(self):
        self.weighted_cycles = 0
        self.instruction_retired = 0
        self.time_ns = 0
        self.ts = 0

    def __str__(self):
        return "ts: " + str(self.ts) + " w:" + str(self.weighted_cycles) \
            + " i:" + str(self.instruction_retired) + " t:" + str(self.time_ns)

class ProcessInfo:

    def __init__(self, num_sockets):
        self.pid = -1
        self.comm = ""
        self.power = 0
        self.cpu_usage = 0
        self.socket_data = []
        self.cgroup_id = ""
        self.container_id = ""

        for i in range(0, num_sockets):
            self.socket_data.append(SocketProcessItem())

    def set_pid(self, pid):
        self.pid = pid

    def set_comm(self, comm):
        self.comm = comm

    def set_power(self, power):
        self.power = power

    def set_cpu_usage(self, cpu_usage):
        self.cpu_usage = cpu_usage

    def compute_cpu_usage_millis(self, total_execution_time_millis):
        self.cpu_usage = (self.get_aggregated_time_ns()/1000000) \
            / total_execution_time_millis

    def set_socket_data_array(self, socket_data_array):
        self.socket_data = socket_data_array

    def set_socket_data(self, socket_index, socket_data):
        self.socket_data[socket_index] = socket_data

    def set_raw_socket_data(self, socket_index, weighted_cycles, \
        instruction_retired, time_ns, ts):
        self.socket_data[socket_index] = \
            SocketProcessItem(weighted_cycles, instruction_retired, time_ns, ts)

    def set_cgroup_id(self, cgroup_id):
        self.cgroup_id = cgroup_id

    def set_container_id(self, container_id):
        self.container_id = container_id

    def reset_socket_data(self):
        for item in self.socket_data:
            item.reset()

    def get_pid(self):
        return self.pid

    def get_comm(self):
        return self.comm

    def get_power(self):
        return self.power

    def get_cpu_usage(self):
        return self.cpu_usage

    def get_socket_data(self, socket_index = -1):
        if socket_index < 0:
            return self.socket_data
        return self.socket_data[socket_index]

    def get_cgroup_id(self):
        return self.cgroup_id

    def get_container_id(self):
        return self.container_id

    def get_aggregated_weighted_cycles(self):
        aggregated = 0
        for item in self.socket_data:
            aggregated = aggregated + item.get_weighted_cycles()
        return aggregated

    def get_aggregated_instruction_retired(self):
        aggregated = 0
        for item in self.socket_data:
            aggregated = aggregated + item.get_instruction_retired()
        return aggregated

    def get_aggregated_time_ns(self):
        aggregated = 0
        for item in self.socket_data:
            aggregated = aggregated + item.get_time_ns()
        return aggregated

    def get_last_ts(self):
        max_ts = 0
        for item in self.socket_data:
            if max_ts < item.get_ts():
                max_ts = item.get_ts()
        return max_ts

    def __str__(self):
        str_rep = str(self.pid) + " comm: " + str(self.comm) \
            + " c_id: " + self.container_id + " p: " + str(self.power) \
            + " u: " + str(self.cpu_usage)

        for socket_item in self.socket_data:
            str_rep = str_rep + " " + str(socket_item)

        return str_rep

    def to_snap(self, request_time):
        metrics_to_be_returned = []

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="thread"),
                snap.NamespaceElement(value=str(self.pid)),
                snap.NamespaceElement(value="pid")
            ],
            version=1,
            description="Weighted cycles",
            data=self.get_aggregated_weighted_cycles(),
            timestamp=request_time
        )
        metrics_to_be_returned.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="thread"),
                snap.NamespaceElement(value=str(self.pid)),
                snap.NamespaceElement(value="instructions")
            ],
            version=1,
            description="Instruction retired",
            data=self.get_aggregated_instruction_retired(),
            timestamp=request_time
        )
        metrics_to_be_returned.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="thread"),
                snap.NamespaceElement(value=str(self.pid)),
                snap.NamespaceElement(value="time_ns")
            ],
            version=1,
            description="Execution time",
            data=self.get_aggregated_time_ns(),
            timestamp=request_time
        )
        metrics_to_be_returned.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="thread"),
                snap.NamespaceElement(value=str(self.pid)),
                snap.NamespaceElement(value="power")
            ],
            version=1,
            description="Power consumption",
            data=self.get_power(),
            timestamp=request_time
        )
        metrics_to_be_returned.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="thread"),
                snap.NamespaceElement(value=str(self.pid)),
                snap.NamespaceElement(value="cpu")
            ],
            version=1,
            description="CPU usage",
            data=self.get_cpu_usage(),
            timestamp=request_time
        )
        metrics_to_be_returned.append(metric)

        return metrics_to_be_returned
