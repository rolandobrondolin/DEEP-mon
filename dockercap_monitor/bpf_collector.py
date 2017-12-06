from bcc import BPF
from bcc import PerfType
from bcc import PerfHWConfig
from proc_topology import BpfProcTopology
from proc_topology import ProcTopology
from process_info import BpfPidStatus
from process_info import SocketProcessItem
from process_info import ProcessInfo
from sample_controller import SampleController
import snap_plugin.v1 as snap
import ctypes as ct
import json
import multiprocessing
import os
import time


class BpfSample:

    def __init__(self, max_ts, total_time, sched_switch_count, timeslice,
                 total_active_power, pid_dict):
        self.max_ts = max_ts
        self.total_execution_time = total_time
        self.sched_switch_count = sched_switch_count
        self.timeslice = timeslice
        self.total_active_power = total_active_power
        self.pid_dict = pid_dict

    def get_total_execution_time(self):
        return self.total_execution_time

    def get_sched_switch_count(self):
        return self.sched_switch_count

    def get_timeslice(self):
        return self.timeslice

    def get_total_active_power(self):
        return self.total_active_power

    def get_pid_dict(self):
        return self.pid_dict

    def __str__(self):
        str_representation = ""

        for key, value in sorted(self.pid_dict.iteritems()):
            str_representation = str_representation + str(value) + "\n"

        str_representation = str_representation + self.get_log_line()

        return str_representation

    def get_log_line(self):
        str_representation = "proc time: " \
            + str(self.total_execution_time) + " sched switch count " \
            + str(self.sched_switch_count) + " timeslice " \
            + str(self.timeslice) + " total active power: " \
            + str(self.total_active_power) + "\n"

        return str_representation

    def get_log_json(self):
        d = {"proc time": str(self.total_execution_time),
             "sched switch count": str(self.sched_switch_count),
             "timeslice": str(self.timeslice),
             "total active power": str(self.total_active_power)
             }
        return json.dumps(d, indent = 4)

        return str_representation

    def to_snap(self):
        metrics_to_be_returned = []
        request_time = time.time()

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="sample"),
                snap.NamespaceElement(value="execution_time"),
            ],
            version=1,
            description="Total execution time",
            data=self.total_execution_time,
            timestamp=request_time
        )
        metrics_to_be_returned.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="sample"),
                snap.NamespaceElement(value="switch_count"),
            ],
            version=1,
            description="Sched switch count",
            data=self.sched_switch_count,
            timestamp=request_time
        )
        metrics_to_be_returned.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="sample"),
                snap.NamespaceElement(value="timeslice"),
            ],
            version=1,
            description="Timeslice",
            data=self.timeslice,
            timestamp=request_time
        )
        metrics_to_be_returned.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="sample"),
                snap.NamespaceElement(value="active_power"),
            ],
            version=1,
            description="Total active power",
            data=self.total_active_power,
            timestamp=request_time
        )
        metrics_to_be_returned.append(metric)

        return metrics_to_be_returned


class ErrorCode(ct.Structure):
    _fields_ = [("err", ct.c_int)]


class BpfCollector:

    def __init__(self, topology, debug):
        self.topology = topology
        self.debug = debug
        bpf_code_path = os.path.dirname(os.path.abspath(__file__)) \
                        + "/bpf/bpf_monitor.c"
        if debug is False:
            self.bpf_program = BPF(src_file=bpf_code_path, \
                cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count(), \
                "-DNUM_SOCKETS=%d" % len(self.topology.get_sockets())])
        else:
            self.bpf_program = BPF(src_file=bpf_code_path, \
                cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count(), \
                "-DNUM_SOCKETS=%d" % len(self.topology.get_sockets()), \
                "-DDEBUG"])

        self.processors = self.bpf_program.get_table("processors")
        self.pids = self.bpf_program.get_table("pids")
        self.idles = self.bpf_program.get_table("idles")
        self.bpf_config = self.bpf_program.get_table("conf")
        self.selector = 0
        self.SELECTOR_DIM = 2
        self.timeslice = 1000000000


        #self.bpf_program["cpu_cycles"].open_perf_event(PerfType.HARDWARE, \
        #    PerfHWConfig.CPU_CYCLES)
        # 4 means RAW_TYPE
        # int("73003c",16) is the hex for UNHALTED_CORE_CYCLES for any thread
        # int("53003c",16) is the hex for UNHALTED_CORE_CYCLES
        # int("5300c0",16) is the hex for INSTRUCTION_RETIRED
        self.bpf_program["cycles_core"].open_perf_event(4, int("73003c",16))
        self.bpf_program["cycles_thread"].open_perf_event(4, int("53003c",16))
        self.bpf_program["instr_thread"].open_perf_event(4, int("5300c0",16))

    def print_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(ErrorCode)).contents
        print str(cpu) + " " + str(event.err)

    def start_capture(self, timeslice):
        for key, value in self.topology.get_new_bpf_topology().iteritems():
            self.processors[ct.c_ulonglong(key)] = value

        self.timeslice = timeslice
        self.bpf_config[ct.c_int(0)] = ct.c_uint(self.selector)     # current selector
        self.bpf_config[ct.c_int(1)] = ct.c_uint(self.selector)     # old selector
        self.bpf_config[ct.c_int(2)] = ct.c_uint(self.timeslice)    # timeslice
        self.bpf_config[ct.c_int(3)] = ct.c_uint(0)                 # switch count

        if self.debug == True:
            self.bpf_program["err"].open_perf_buffer(self.print_event, page_cnt=256)

        self.bpf_program.attach_tracepoint(tp="sched:sched_switch", \
            fn_name="trace_switch")
        self.bpf_program.attach_tracepoint(tp="sched:sched_process_exit", \
            fn_name="trace_exit")

    def stop_capture(self):
        self.bpf_program.detach_tracepoint(tp="sched:sched_switch")
        self.bpf_program.detach_tracepoint(tp="sched:sched_process_exit")

    def get_new_sample(self, sample_controller, rapl_monitor):
        sample = self._get_new_sample(rapl_monitor)
        sample_controller.compute_sleep_time(sample.get_sched_switch_count())
        self.timeslice = sample_controller.get_timeslice()
        self.bpf_config[ct.c_int(2)] = ct.c_uint(self.timeslice)    # timeslice

        if self.debug == True:
            self.bpf_program.kprobe_poll()

        return sample

    def _get_new_sample(self, rapl_monitor):

        total_execution_time = 0.0
        sched_switch_count = self.bpf_config[ct.c_int(3)].value
        tsmax = 0

        total_weighted_cycles = []
        for socket in self.topology.get_sockets():
            total_weighted_cycles.append(0)

        read_selector = 0
        total_slots_length = len(self.topology.get_sockets())*self.SELECTOR_DIM

        if self.selector == 0:
            self.selector = 1
            read_selector = 0
        else:
            self.selector = 0
            read_selector = 1

        # get new sample from rapl right before changing selector
        rapl_diff = rapl_monitor.get_sample()
        self.bpf_config[ct.c_int(0)] = ct.c_uint(self.selector)

        pid_dict = {}

        for key, data in self.pids.items():
            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):
                # search max timestamp of the sample
                if data.ts[multisocket_selector] > tsmax:
                    tsmax = data.ts[multisocket_selector]

        for key, data in self.idles.items():
            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):
                # search max timestamp of the sample
                if data.ts[multisocket_selector] > tsmax:
                    tsmax = data.ts[multisocket_selector]

        for key, data in self.pids.items():
            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):
                # Compute the number of total weighted cycles per socket
                cycles_index = int(multisocket_selector/self.SELECTOR_DIM)
                if data.ts[multisocket_selector] + self.timeslice > tsmax:
                    total_weighted_cycles[cycles_index] = \
                        total_weighted_cycles[cycles_index] \
                        + data.weighted_cycles[multisocket_selector]

                    total_execution_time = total_execution_time \
                        + float(data.time_ns[multisocket_selector])/1000000

        for key, data in self.idles.items():
            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):
                # Compute the number of total weighted cycles per socket
                cycles_index = int(multisocket_selector/self.SELECTOR_DIM)
                if data.ts[multisocket_selector] + self.timeslice > tsmax:
                    total_weighted_cycles[cycles_index] = \
                        total_weighted_cycles[cycles_index] \
                        + data.weighted_cycles[multisocket_selector]

                    total_execution_time = total_execution_time \
                        + float(data.time_ns[multisocket_selector])/1000000

        power= [rapl_diff[skt].power()*1000 for skt in self.topology.get_sockets()]
        total_power = sum(power)

        for key, data in self.pids.items():

            proc_info = ProcessInfo(len(self.topology.get_sockets()))
            proc_info.set_pid(data.pid)
            proc_info.set_comm(data.comm)
            add_proc = False

            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):

                if data.ts[multisocket_selector] + self.timeslice > tsmax:
                    socket_info = SocketProcessItem()
                    socket_info.set_weighted_cycles(\
                        data.weighted_cycles[multisocket_selector])
                    socket_info.set_time_ns(data.time_ns[multisocket_selector])
                    socket_info.set_instruction_retired(\
                        data.instruction_retired[multisocket_selector])
                    socket_info.set_ts(data.ts[multisocket_selector])
                    proc_info.set_socket_data(\
                        multisocket_selector/self.SELECTOR_DIM, socket_info)

                    add_proc = True
            if add_proc:
                pid_dict[data.pid] = proc_info
                proc_info.set_power(self._get_pid_power(proc_info, \
                    total_weighted_cycles, power))
                proc_info.compute_cpu_usage_millis(float(total_execution_time))


        for key, data in self.idles.items():

            proc_info = ProcessInfo(len(self.topology.get_sockets()))
            proc_info.set_pid(data.pid)
            proc_info.set_comm(data.comm)
            add_proc = False

            for multisocket_selector in \
                range(read_selector, total_slots_length, self.SELECTOR_DIM):

                if data.ts[multisocket_selector] + self.timeslice > tsmax:

                    socket_info = SocketProcessItem()
                    socket_info.set_weighted_cycles(\
                        data.weighted_cycles[multisocket_selector])
                    socket_info.set_instruction_retired(\
                        data.instruction_retired[multisocket_selector])
                    socket_info.set_time_ns(data.time_ns[multisocket_selector])
                    socket_info.set_ts(data.ts[multisocket_selector])
                    proc_info.set_socket_data(\
                        multisocket_selector/self.SELECTOR_DIM, socket_info)

                    add_proc = True
            if add_proc:
                pid_dict[-1 * (1 + int(key.value))] = proc_info
                proc_info.set_power(self._get_pid_power(proc_info, \
                    total_weighted_cycles, power))
                proc_info.compute_cpu_usage_millis(float(total_execution_time))

        return BpfSample(tsmax, total_execution_time, sched_switch_count, \
            self.timeslice, total_power, pid_dict)

    def _get_pid_power(self, pid, total_cycles, power):

        pid_power = 0
        for socket in self.topology.get_sockets():
            pid_power = pid_power + (power[socket] * \
                (float(pid.get_socket_data(socket).get_weighted_cycles()) \
                / float(total_cycles[socket])))
        return pid_power
