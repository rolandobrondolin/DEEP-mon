import ctypes as ct

class BpfPidStatus(ct.Structure):
    TASK_COMM_LEN = 16
    socket_size = 0
    _fields_ = [("pid", ct.c_int),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("weighted_cycles", ct.c_ulonglong * 2 * socket_size),
                ("time_ns", ct.c_ulonglong * 2 * socket_size),
                ("bpf_selector", ct.c_int),
                ("ts", ct.c_ulonglong * 2 * socket_size)]

    def __init__(self, socket_size):
        self.socket_size = socket_size

class SocketProcessItem:

    def __init__(self, weighted_cycles = 0, time_ns = 0, ts = 0):
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

    def __str__(self):
        return "ts: " + str(self.ts) + " w:" + str(self.weighted_cycles) \
            + " t:" + str(self.time_ns)

class ProcessInfo:

    def __init__(self, num_sockets):
        self.pid = -1
        self.comm = ""
        self.power = 0
        self.socket_data = []

        for i in range(0, num_sockets):
            self.socket_data.append(SocketProcessItem())

    def set_pid(self, pid):
        self.pid = pid

    def set_comm(self, comm):
        self.comm = comm

    def set_power(self, power):
        self.power = power

    def set_socket_data(self, socket_index, socket_data):
        self.socket_data[socket_index] = socket_data

    def set_raw_socket_data(self, socket_index, weighted_cycles, time_ns, ts):
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

    def __str__(self):
        str_rep = str(self.pid) + " comm: " + str(self.comm) \
            + " p: " + str(self.power)

        for socket_item in self.socket_data:
            str_rep = str_rep + " " + str(socket_item)

        return str_rep
