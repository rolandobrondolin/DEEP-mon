from bcc import BPF
from bcc import PerfType
from bcc import PerfHWConfig
import multiprocessing
import ctypes as ct
import os
from proc_topology import BpfProcTopology
from proc_topology import ProcTopology
from process_info import BpfPidStatus
from process_info import SocketProcessItem
from process_info import ProcessInfo

class BpfSample:

    def __init__(self, total_time, sched_switch_count, timeslice, pid_dict):
        self.total_execution_time = total_time
        self.sched_switch_count = sched_switch_count
        self.timeslice = timeslice
        self.pid_dict = pid_dict

    def get_total_execution_time(self):
        return self.total_execution_time

    def get_sched_switch_count(self):
        return self.sched_switch_count

    def get_timeslice(self):
        return self.timeslice

    def get_pid_dict(self):
        return self.pid_dict

    def __str__(self):
        str_representation = "proc time: " + str(self.total_execution_time) \
            + " sched switch count " + str(self.sched_switch_count) \
            + " timeslice " + str(self.timeslice) + "\n"

        for key, value in self.pid_dict.iteritems():
            str_representation = str_representation + str(value) + "\n"

        return str_representation


class BpfCollector:

    def __init__(self, topology):
        self.topology = topology
        self.bpf_program = BPF(src_file="bpf/bpf_monitor.c", \
            cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count(), \
            "-DNUM_SOCKETS=%d" % len(self.topology.get_sockets())])

        self.processors = self.bpf_program.get_table("processors")
        self.pids = self.bpf_program.get_table("pids")
        self.idles = self.bpf_program.get_table("idles")
        self.bpf_config = self.bpf_program.get_table("conf")
        self.selector = 0
        self.SELECTOR_DIM = 2
        self.timeslice = 1000000000

        self.bpf_program["cpu_cycles"].open_perf_event(PerfType.HARDWARE, \
            PerfHWConfig.CPU_CYCLES)

    def start_capture(self):
        for key, value in self.topology.get_new_bpf_topology().iteritems():
            self.processors[ct.c_ulonglong(key)] = value

        self.timeslice = 1000000000
        self.bpf_config[ct.c_int(0)] = ct.c_uint(self.selector)     # current selector
        self.bpf_config[ct.c_int(1)] = ct.c_uint(self.selector)     # old selector
        self.bpf_config[ct.c_int(2)] = ct.c_uint(self.timeslice)    # timeslice
        self.bpf_config[ct.c_int(3)] = ct.c_uint(0)                 # switch count

        self.bpf_program.attach_tracepoint(tp="sched:sched_switch", \
            fn_name="trace_switch")
        self.bpf_program.attach_tracepoint(tp="sched:sched_process_exit", \
            fn_name="trace_exit")

    def stop_capture(self):
        self.bpf_program.detach_tracepoint(tp="sched:sched_switch")
        self.bpf_program.detach_tracepoint(tp="sched:sched_process_exit")

    def get_new_sample(self, new_timeslice):
        sample = self.get_new_sample()
        self.timeslice = new_timeslice
        self.bpf_config[ct.c_int(2)] = ct.c_uint(self.timeslice)    # timeslice

        return sample

    def get_new_sample(self):

        total_execution_time = 0.0
        sched_switch_count = self.bpf_config[ct.c_int(3)].value
        tsmax = 0
        read_selector = 0
        total_slots_length = len(self.topology.get_sockets())*self.SELECTOR_DIM

        if self.selector == 0:
            self.selector = 1
            read_selector = 0
        else:
            self.selector = 0
            read_selector = 1

        self.bpf_config[ct.c_int(0)] = ct.c_uint(self.selector)

        pid_dict = {}

        for key, data in self.pids.items():
            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):
                if data.ts[multisocket_selector] > tsmax:
                    tsmax = data.ts[multisocket_selector]
        for key, data in self.idles.items():
            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):
                if data.ts[multisocket_selector] > tsmax:
                    tsmax = data.ts[multisocket_selector]

        for key, data in self.pids.items():

            proc_info = ProcessInfo(len(self.topology.get_sockets()))
            proc_info.set_pid(data.pid)
            proc_info.set_comm(data.comm)

            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):

                if data.ts[multisocket_selector] + self.timeslice > tsmax:
                    total_execution_time = total_execution_time \
                        + float(data.time_ns[multisocket_selector])/1000000

                    socket_info = SocketProcessItem()
                    socket_info.set_weighted_cycles(\
                        data.weighted_cycles[multisocket_selector])
                    socket_info.set_time_ns(data.time_ns[multisocket_selector])
                    socket_info.set_ts(data.ts[multisocket_selector])
                    proc_info.set_socket_data(\
                        multisocket_selector/self.SELECTOR_DIM, socket_info)

            pid_dict[data.pid] = proc_info

        for key, data in self.idles.items():

            proc_info = ProcessInfo(len(self.topology.get_sockets()))
            proc_info.set_pid(data.pid)
            proc_info.set_comm(data.comm)

            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):

                if data.ts[multisocket_selector] + self.timeslice > tsmax:
                    total_execution_time = total_execution_time \
                        + float(data.time_ns[multisocket_selector])/1000000

                    socket_info = SocketProcessItem()
                    socket_info.set_weighted_cycles(\
                        data.weighted_cycles[multisocket_selector])
                    socket_info.set_time_ns(data.time_ns[multisocket_selector])
                    socket_info.set_ts(data.ts[multisocket_selector])
                    proc_info.set_socket_data(\
                        multisocket_selector/self.SELECTOR_DIM, socket_info)

            pid_dict[-1 * (1 + int(key.value))] = proc_info

        return BpfSample(total_execution_time, sched_switch_count, \
            self.timeslice, pid_dict)
