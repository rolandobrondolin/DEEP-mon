from __future__ import print_function
from bcc import BPF, PerfType, PerfHWConfig, PerfSWConfig
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


class bcolors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class BpfSample:

    def __init__(self, max_ts, total_time, sched_switch_count, timeslice,
                 total_active_power, pid_dict, cpu_cores):
        self.max_ts = max_ts
        self.total_execution_time = total_time
        self.sched_switch_count = sched_switch_count
        self.timeslice = timeslice
        self.total_active_power = total_active_power
        self.pid_dict = pid_dict
        self.cpu_cores = cpu_cores

    def get_max_ts(self):
        return self.max_ts

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

    def get_cpu_cores(self):
        return self.cpu_cores

    def __str__(self):
        str_representation = ""

        for key, value in sorted(self.pid_dict.iteritems()):
            str_representation = str_representation + str(value) + "\n"

        str_representation = str_representation + self.get_log_line()

        return str_representation

    def get_log_line(self):
        str_representation = (
                bcolors.YELLOW + "PROC TIME: " + bcolors.ENDC
                + "{:.3f}".format(self.total_execution_time)
                + "\t" + bcolors.YELLOW + "SCHED SWITCH COUNT: " + bcolors.ENDC
                + str(self.sched_switch_count)
                + "\t" + bcolors.YELLOW + "TIMESLICE: " + bcolors.ENDC
                + str(self.timeslice / 1000000000) + "s"
                + "\n\t" + bcolors.GREEN + "TOTAL PACKAGE ACTIVE POWER:\t" + bcolors.ENDC
                + "{:.3f}".format(self.total_active_power["package"])
                + "\n\t" + bcolors.GREEN + "TOTAL CORE ACTIVE POWER:\t" + bcolors.ENDC
                + "{:.3f}".format(self.total_active_power["core"])
                + "\n\t" + bcolors.GREEN + "TOTAL DRAM ACTIVE POWER:\t" + bcolors.ENDC
                + "{:.3f}".format(self.total_active_power["dram"])
                )
        return str_representation

    def get_log_json(self):
        d = {"PROC TIME": str(self.total_execution_time),
             "SCHED SWITCH COUNT": str(self.sched_switch_count),
             "TIMESLICE": str(self.timeslice),
             "TOTAL PACKAGE ACTIVE POWER": str(self.total_active_power["package"]),
             "TOTAL CORE ACTIVE POWER": str(self.total_active_power["core"]),
             "TOTAL DRAM ACTIVE POWER": str(self.total_active_power["dram"])
             }
        return json.dumps(d, indent=4)


    def _get_summary(self, request_time, snap_namespace):
        perf_summary = {
            "execution_time": {"value": self.total_execution_time, "strategy": "sum", "type": "int64"},
            "switch_count": {"value": self.sched_switch_count, "strategy": "sum", "type": "int64"},
            "timeslice": {"value": self.timeslice, "strategy": "sum", "type": "int64"},
            "package_power": {"value": self.total_active_power["package"], "strategy": "sum", "type": "int64"},
            "core_power": {"value": self.total_active_power["core"], "strategy": "sum", "type": "int64"},
            "dram_power": {"value": self.total_active_power["dram"], "strategy": "sum", "type": "int64"},
            "cpu_cores": {"value": self.cpu_cores, "strategy": "sum", "type": "int64"}
        }
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Performance summary",
            data=json.dumps(perf_summary),
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
            snap.NamespaceElement(value="host"),
            snap.NamespaceElement(value="summary"),
        ]
        metrics_to_be_returned.append(self._get_summary(request_time, namespace))
        return metrics_to_be_returned


class ErrorCode(ct.Structure):
    _fields_ = [("err", ct.c_int)]

class BPFErrors:
    error_dict = {-1: "BPF_PROCEED_WITH_DEBUG_MODE", \
        -2: "BPF_SELECTOR_NOT_IN_PLACE", \
        -3: "OLD_BPF_SELECTOR_NOT_IN_PLACE", \
        -4: "TIMESTEP_NOT_IN_PLACE", \
        -5: "CORRUPTED_TOPOLOGY_MAP", \
        -6: "WRONG_SIBLING_TOPOLOGY_MAP", \
        -7: "THREAD_MIGRATED_UNEXPECTEDLY"}


class BpfCollector:

    def __init__(self, topology, debug, power_measure):
        self.topology = topology
        self.debug = debug
        self.power_measure = power_measure
        bpf_code_path = os.path.dirname(os.path.abspath(__file__)) \
                        + "/bpf/bpf_monitor.c"
        if debug is False:
            if self.power_measure == True:
                self.bpf_program = BPF(src_file=bpf_code_path, \
                    cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count(), \
                    "-DNUM_SOCKETS=%d" % len(self.topology.get_sockets()), \
                    "-DPERFORMANCE_COUNTERS"])
            else:
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
        self.bpf_global_timestamps = self.bpf_program.get_table("global_timestamps")
        self.selector = 0
        self.SELECTOR_DIM = 2
        self.timeslice = 1000000000
        self.timed_capture = False

        #self.bpf_program["cpu_cycles"].open_perf_event(PerfType.HARDWARE, \
        #    PerfHWConfig.CPU_CYCLES)
        # 4 means RAW_TYPE
        # int("73003c",16) is the hex for UNHALTED_CORE_CYCLES for any thread
        # int("53003c",16) is the hex for UNHALTED_CORE_CYCLES
        # int("5300c0",16) is the hex for INSTRUCTION_RETIRED
        if self.power_measure == True:
            self.bpf_program["cycles_core"].open_perf_event(4, int("73003c",16))
            self.bpf_program["cycles_thread"].open_perf_event(4, int("53003c",16))
            self.bpf_program["instr_thread"].open_perf_event(4, int("5300c0",16))
            self.bpf_program["cache_misses"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CACHE_MISSES)
            self.bpf_program["cache_refs"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CACHE_REFERENCES)


    def print_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(ErrorCode)).contents
        if event.err >= 0:
            print("core: " + str(cpu) + " topology counters overflow or initialized with pid: " + str(event.err))
        elif event.err < -1:
            # exclude the BPF_PROCEED_WITH_DEBUG_MODE event, since it is used
            # just to advance computation for the timed capture
            print("core: " + str(cpu) + " " + str(BPFErrors.error_dict[event.err]))


    def start_capture(self, timeslice):
        for key, value in self.topology.get_new_bpf_topology().iteritems():
            self.processors[ct.c_ulonglong(key)] = value

        self.timed_capture = False
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

    def start_timed_capture(self, count=0, frequency=0):
        if frequency:
            sample_freq = frequency
            sample_period = 0
            self.timeslice = int((1 / float(frequency)) * 1000000000)
        elif count:
            sample_freq = 0
            sample_period = count
            self.timeslice = int(sample_period * 1000000000)
        else:
            # If user didn't specify anything, use default 49Hz sampling
            sample_freq = 49
            sample_period = 0
            self.timeslice = int((1 / float(frequency)) * 1000000000)

        self.timed_capture = True

        for key, value in self.topology.get_new_bpf_topology().iteritems():
            self.processors[ct.c_ulonglong(key)] = value

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
        self.bpf_program.attach_perf_event(ev_type=PerfType.SOFTWARE,
                ev_config=PerfSWConfig.CPU_CLOCK, fn_name="timed_trace",
                sample_period=sample_period, sample_freq=sample_freq)

    def stop_capture(self):
        self.bpf_program.detach_tracepoint(tp="sched:sched_switch")
        self.bpf_program.detach_tracepoint(tp="sched:sched_process_exit")

    def get_new_sample(self, sample_controller, rapl_monitor):
        sample = self._get_new_sample(rapl_monitor)
        if not self.timed_capture:
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

        # Initialize the weighted cycles for each core to 0
        total_weighted_cycles = []
        for socket in self.topology.get_sockets():
            total_weighted_cycles.append(0)

        # We use a binary selector so that while userspace is reading events
        # using selector 0 we write events using selector 1 and vice versa.
        # Here we initialize it to 0 and set the number of slots used for
        # read/write equal to the number of sockets * the number of selectors
        read_selector = 0
        total_slots_length = len(self.topology.get_sockets())*self.SELECTOR_DIM

        # Every time we get a new sample we want to switch the selector we are using
        if self.selector == 0:
            self.selector = 1
            read_selector = 0
        else:
            self.selector = 0
            read_selector = 1

        rapl_measurement = []
        package_diff = 0
        core_diff = 0
        dram_diff = 0
        if self.power_measure == True:
            # Get new sample from rapl right before changing selector in eBPF
            rapl_measurement = rapl_monitor.get_rapl_measure()

            package_diff = rapl_measurement["package"]
            core_diff = rapl_measurement["core"]
            dram_diff = rapl_measurement["dram"]

        # Propagate the update of the selector to the eBPF program
        self.bpf_config[ct.c_int(0)] = ct.c_uint(self.selector)

        pid_dict = {}

        tsmax = self.bpf_global_timestamps[ct.c_int(read_selector)].value


        # Add the count of clock cycles for each active process to the total
        # number of clock cycles of the socket
        for key, data in self.pids.items():
            if data.ts[read_selector] + self.timeslice > tsmax:
                total_execution_time = total_execution_time + float(data.time_ns[read_selector])/1000000

            if self.power_measure == True:
                for multisocket_selector in range(read_selector, total_slots_length, self.SELECTOR_DIM):
                    # Compute the number of total weighted cycles per socket
                    cycles_index = int(multisocket_selector/self.SELECTOR_DIM)
                    if data.ts[read_selector] + self.timeslice > tsmax:
                        total_weighted_cycles[cycles_index] = total_weighted_cycles[cycles_index] + data.weighted_cycles[multisocket_selector]

        # Add the count of clock cycles for each idle process to the total
        # number of clock cycles of the socket
        for key, data in self.idles.items():
            if data.ts[read_selector] + self.timeslice > tsmax:
                total_execution_time = total_execution_time + float(data.time_ns[read_selector])/1000000

            if self.power_measure == True:
                for multisocket_selector in range(read_selector, total_slots_length, self.SELECTOR_DIM):
                    # Compute the number of total weighted cycles per socket
                    cycles_index = int(multisocket_selector/self.SELECTOR_DIM)
                    if data.ts[read_selector] + self.timeslice > tsmax:
                        total_weighted_cycles[cycles_index] = total_weighted_cycles[cycles_index] + data.weighted_cycles[multisocket_selector]

        if self.power_measure == True:
            # Compute package/core/dram power in mW from RAPL samples
            package_power = [package_diff[skt].power_milliw()
                             for skt in self.topology.get_sockets()]
            core_power = [core_diff[skt].power_milliw()
                          for skt in self.topology.get_sockets()]
            dram_power = [dram_diff[skt].power_milliw()
                          for skt in self.topology.get_sockets()]
            total_power = {
                    "package": sum(package_power),
                    "core": sum(core_power),
                    "dram": sum(dram_power)
                    }
        else:
            total_power = {
                    "package": 0,
                    "core": 0,
                    "dram": 0
                    }

        for key, data in self.pids.items():

            proc_info = ProcessInfo(len(self.topology.get_sockets()))
            proc_info.set_pid(data.pid)
            proc_info.set_tgid(data.tgid)
            proc_info.set_comm(data.comm)
            proc_info.set_cycles(data.cycles[read_selector])
            proc_info.set_instruction_retired(data.instruction_retired[read_selector])
            proc_info.set_cache_misses(data.cache_misses[read_selector])
            proc_info.set_cache_refs(data.cache_refs[read_selector])
            proc_info.set_time_ns(data.time_ns[read_selector])
            add_proc = False

            for multisocket_selector in range(read_selector, total_slots_length, self.SELECTOR_DIM):

                if data.ts[read_selector] + self.timeslice > tsmax:
                    socket_info = SocketProcessItem()
                    socket_info.set_weighted_cycles(data.weighted_cycles[multisocket_selector])
                    socket_info.set_ts(data.ts[read_selector])
                    proc_info.set_socket_data(multisocket_selector/self.SELECTOR_DIM, socket_info)
                    add_proc = True

            if add_proc:
                pid_dict[data.pid] = proc_info

                if self.power_measure == True:
                    proc_info.set_power(self._get_pid_power(proc_info, total_weighted_cycles, core_power))
                else:
                    proc_info.set_power(0)
                proc_info.compute_cpu_usage_millis(float(total_execution_time), multiprocessing.cpu_count())

        for key, data in self.idles.items():

            proc_info = ProcessInfo(len(self.topology.get_sockets()))
            proc_info.set_pid(data.pid)
            proc_info.set_tgid(-1 * (1 + int(key.value)))
            proc_info.set_comm(data.comm)
            proc_info.set_cycles(data.cycles[read_selector])
            proc_info.set_instruction_retired(data.instruction_retired[read_selector])
            proc_info.set_cache_misses(data.cache_misses[read_selector])
            proc_info.set_cache_refs(data.cache_refs[read_selector])
            proc_info.set_time_ns(data.time_ns[read_selector])
            add_proc = False

            for multisocket_selector in range(read_selector, total_slots_length, self.SELECTOR_DIM):

                if data.ts[read_selector] + self.timeslice > tsmax:

                    socket_info = SocketProcessItem()
                    socket_info.set_weighted_cycles(data.weighted_cycles[multisocket_selector])
                    socket_info.set_ts(data.ts[read_selector])
                    proc_info.set_socket_data(multisocket_selector/self.SELECTOR_DIM, socket_info)
                    add_proc = True

            if add_proc:
                pid_dict[-1 * (1 + int(key.value))] = proc_info
                if self.power_measure == True:
                    proc_info.set_power(self._get_pid_power(proc_info, total_weighted_cycles, core_power))
                else:
                    proc_info.set_power(0)
                proc_info.compute_cpu_usage_millis(float(total_execution_time), multiprocessing.cpu_count())

        return BpfSample(tsmax, total_execution_time, sched_switch_count, self.timeslice, total_power, pid_dict, self.topology.get_hyperthread_count())

    def _get_pid_power(self, pid, total_cycles, core_power):

        pid_power = 0
        for socket in self.topology.get_sockets():
            if float(total_cycles[socket]) > 0:
                pid_power = pid_power + (core_power[socket] * \
                    (float(pid.get_socket_data(socket).get_weighted_cycles()) \
                    / float(total_cycles[socket])))
        return pid_power
