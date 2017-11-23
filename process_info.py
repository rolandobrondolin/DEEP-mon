import ctypes as ct

class BpfPidStatus(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("weighted_cycles", ct.c_ulonglong * 2 * len(socket_set)),
                ("time_ns", ct.c_ulonglong * 2 * len(socket_set)),
                ("bpf_selector", ct.c_int),
                ("ts", ct.c_ulonglong * 2 * len(socket_set))]

class SocketProcessItem:

    def __init__(self):
        self.weighted_cycles = 0
        self.time_ns = 0
        self.ts = 0

    def __init__(self, weighted_cycles, time_ns, ts):
        self.weighted_cycles = weighted_cycles
        self.time_ns = time_ns
        self.ts = ts

    def set_weighted_cycles(self, weighted_cycles):
        self.weighted_cycles = weighted_cycles

    def set_time_ns(self, time_ns):
        self.time_ns = time_ns

    def set_ts(self, ts):
        self.ts = ts

    def get_weighted_cycles(self):
        return self.weighted_cycles

    def get_time_ns(self):
        return self.time_ns

    def get_ts(self):
        return ts

class ProcessInfo:

    def __init__(self, num_sockets):
        self.pid = -1
        self.comm = ""
        self.power = 0
        self.socket_data = []

        for i in range(0, num_sockets):
            self.socket_data[i] = SocketProcessItem()

    def set_pid(self, pid):
        self.pid = pid

    def set_comm(self, comm):
        self.comm = comm

    def set_power(self, power):
        self.power = power

    def set_socket_data(self, socket_index, socket_data):
        self.socket_data[socket_index] = socket_data

    def set_socket_data(self, socket_index, weighted_cycles, time_ns, ts):
        self.socket_data[socket_index] = \
            SocketProcessItem(weighted_cycles, time_ns, ts)

    def get_pid(self):
        return self.pid

    def get_comm(self):
        return self.comm

    def get_power(self):
        return self.power

    def get_socket_data(self):
        return self.socket_data

    def get_socket_data(self, socket_index):
        return self.socket_data[socket_index]
