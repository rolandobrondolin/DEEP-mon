# -*- coding: utf-8 -*-

from bcc import BPF, PerfType, PerfHWConfig
import multiprocessing
import ctypes as ct
import os
import time
# from rapl import rapl
from rapl import raplhardcoded

debug = False
TASK_COMM_LEN = 16

# parse /proc/cpuinfo to obtain processor topology
ht_id = 0
sibling_id = 0
core_id = 0
processor_id = 0

coresDict = {} #core elem is organized as ht_id, sibling_id, core_id, processor_id
socket_set = set()

with open('/proc/cpuinfo') as f:
    for line in f:
        sp = line.split(" ")
        if "processor\t" in sp[0]:
            ht_id = int(sp[1])
        if "physical" in sp[0] and "id\t" in sp[1]:
            processor_id = int(sp[2])
            socket_set.add(processor_id)
        if "core" in sp[0] and "id\t\t" in sp[1]:
            core_id = int(sp[2])
            found = False
            for key, value in coresDict.iteritems():
                if value[2] == core_id and value[3] == processor_id:
                    found = True
                    value[1] = ht_id
                    coresDict[ht_id] = [ht_id, value[0], core_id, processor_id, 0, 0, -1]
                    break
            if not found:
                coresDict[ht_id] = [ht_id, -1, core_id, processor_id, 0, 0, -1]

if debug:
    for key, value in coresDict.items():
        print value


class ProcTopology(ct.Structure):
    _fields_ = [("ht_id", ct.c_ulonglong),
                ("sibling_id", ct.c_ulonglong),
                ("core_id", ct.c_ulonglong),
                ("processor_id", ct.c_ulonglong),
                ("cycles", ct.c_ulonglong),
                ("ts", ct.c_ulonglong),
                ("running_pid", ct.c_int)]

class PidStatus(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("weighted_cycles", ct.c_ulonglong * 2 * len(socket_set)),
                ("time_ns", ct.c_ulonglong * 2 * len(socket_set)),
                ("bpf_selector", ct.c_int),
                ("ts", ct.c_ulonglong * 2 * len(socket_set))]

class ErrorCode(ct.Structure):
    _fields_ = [("err", ct.c_int)]

#Load BPF program
bpf_program = BPF(src_file="bpf/bpf_monitor.c", cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count(), "-DNUM_SOCKETS=%d" % len(socket_set)])
# Open cycles PMC
bpf_program["cpu_cycles"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)
# get tables
processors = bpf_program.get_table("processors")
pids = bpf_program.get_table("pids")
idles = bpf_program.get_table("idles")
conf = bpf_program.get_table("conf")
# set default bpf_selector
timeslice = 1000000000
conf[ct.c_int(0)] = ct.c_uint(1)
conf[ct.c_int(1)] = ct.c_uint(1)
conf[ct.c_int(2)] = ct.c_uint(timeslice)
conf[ct.c_int(3)] = ct.c_uint(0)

# populate processors hash with proc topology
for key, value in coresDict.iteritems():
    core = ProcTopology(ct.c_ulonglong(value[0]), ct.c_ulonglong(value[1]),     \
        ct.c_ulonglong(value[2]), ct.c_ulonglong(value[3]), ct.c_ulonglong(0),  \
        ct.c_ulonglong(0), ct.c_int(0))
    processors[ct.c_ulonglong(key)] = core

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ErrorCode)).contents
    print str(cpu) + " " + str(event.err)

# attach TRACEPOINT
bpf_program.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_switch")
bpf_program.attach_tracepoint(tp="sched:sched_process_exit", fn_name="trace_exit")
# attach error buffer
if debug == True:
    bpf_program["err"].open_perf_buffer(print_event, page_cnt=256)
time_to_sleep = timeslice / 1000000000
# sleep and retrieve data

rapl_reader = raplhardcoded.RaplReader()

while True:
    # Sample initial energy consumption from RAPL
    # rapl_sample_start = rapl_reader.read_energy_core_sample("0")
    # d = {key: "{}".format(key) for key in range(1,4)}
    rapl_sample_start = {key: rapl_reader.read_energy_core_sample(str(key)) for key in range(0, len(socket_set))}
    # rapl_sample_start = { 
         # 0: rapl_reader.read_energy_core_sample("0"),
         # 1: rapl_reader.read_energy_core_sample("1") }

    time.sleep(time_to_sleep)

    # Sample final energy consumption from RAPL
    rapl_sample_end = {key: rapl_reader.read_energy_core_sample(str(key)) for key in range(0, len(socket_set))}
    # rapl_sample_end = {
         # 0: rapl_reader.read_energy_core_sample("0"),
         # 1: rapl_reader.read_energy_core_sample("1") }

    # Find the difference between the two samples to compute power
    rapl_diff = {key: rapl_sample_end[key] - rapl_sample_start[key] for key in range(0, len(socket_set))}
    # rapl_diff = {
        # 0: rapl_sample_end[0] - rapl_sample_start[0],
        # 1: rapl_sample_end[1] - rapl_sample_start[1] }
    

    power_millis = {key: rapl_diff[key].power()*1000 for key in range(0, len(socket_set))}
    # power_millis = {
        # 0: rapl_diff[0].power()*1000,
        # 1: rapl_diff[1].power()*1000 }
    
    power_micro = {key: rapl_diff[key].power()*1000000 for key in range(0, len(socket_set))}
    # power_micro = {
        # 0: rapl_diff[0].power()*1000000,
        # 1: rapl_diff[1].power()*1000000 }

    # Use a reduce to sum all the weighted cycles for each pid
    # in order to find the total number of weighted cycles for the socket
    weighted_socket_cycles = {ext_key: reduce(lambda x, y: x+1+y, [pid.weighted_cycles[ext_key] for key, pid in pids.items()])  for ext_key in range(0, len(socket_set))}
    # weighted_socket_cycles = {
        # 0: reduce(lambda x, y: x+1+y, [pid.weighted_cycles[0] for key, pid in pids.items()]),
        # 1: reduce(lambda x, y: x+1+y, [pid.weighted_cycles[1] for key, pid in pids.items()]) }

    start_time = time.time()
    # print debug stuff
    if debug == True:
        bpf_program.kprobe_poll()
    i = 0.0

    sched_switch_count = conf[ct.c_int(3)].value

    print conf[ct.c_int(0)].value
    if conf[ct.c_int(0)].value == 0:
        conf[ct.c_int(0)] = ct.c_uint(1)

        tsmax = 0
        for key, data in pids.items():
            for socket_ts in data.ts:
                if socket_ts > tsmax:
                    tsmax = socket_ts
        for key, data in idles.items():
            for socket_ts in data.ts:
                if socket_ts > tsmax:
                    tsmax = socket_ts

        for key, data in pids.items():
            printed_str = str(data.pid) + " " + str(data.comm) + " " + str(data.bpf_selector) + " "
            for multisocket_selector in range(0, len(socket_set)*2, 2):
                if data.ts[multisocket_selector] + timeslice > tsmax:
                    i = i + float(data.time_ns[multisocket_selector])/1000000
                printed_str = (printed_str + str(data.ts[multisocket_selector])
                    + " " + str(data.weighted_cycles[multisocket_selector])
                    + " " + str(float(data.time_ns[multisocket_selector])/1000000)
                    + "  {:.3f}".format((float(data.weighted_cycles[multisocket_selector])
                        / float(weighted_socket_cycles[multisocket_selector/2]) * power_millis[multisocket_selector/2])) + "mW" + " ")
            print printed_str
        print ""
        for key, data in idles.items():
            printed_str = str(data.pid) + " " + str(data.comm) + " " + str(data.bpf_selector) + " "
            for multisocket_selector in range(0, len(socket_set)*2, 2):
                if data.ts[multisocket_selector] + timeslice > tsmax:
                    i = i + float(data.time_ns[multisocket_selector])/1000000
                printed_str = ( printed_str + str(data.ts[multisocket_selector])
                    + " " + str(data.weighted_cycles[multisocket_selector])
                    + " " + str(float(data.time_ns[multisocket_selector])/1000000)
                    + "  {:.3f}".format((float(data.weighted_cycles[multisocket_selector])
                        / float(weighted_socket_cycles[multisocket_selector/2]) * power_millis[multisocket_selector/2])) + "mW" + " ")
                print printed_str
        print ""

    else:
        conf[ct.c_int(0)] = ct.c_uint(0)
        tsmax = 0
        for key, data in pids.items():
            for socket_ts in data.ts:
                if socket_ts > tsmax:
                    tsmax = socket_ts
        for key, data in idles.items():
            for socket_ts in data.ts:
                if socket_ts > tsmax:
                    tsmax = socket_ts

        for key, data in pids.items():
            printed_str = str(data.pid) + " " + str(data.comm) + " " + str(data.bpf_selector) + " "
            for multisocket_selector in range(1, len(socket_set)*2, 2):
                if data.ts[multisocket_selector] + timeslice > tsmax:
                    i = i + float(data.time_ns[multisocket_selector])/1000000
                printed_str = ( printed_str + str(data.ts[multisocket_selector])
                    + " " + str(data.weighted_cycles[multisocket_selector])
                    + " " + str(float(data.time_ns[multisocket_selector])/1000000)
                    + "  {:.3f}".format((float(data.weighted_cycles[multisocket_selector])
                        / float(weighted_socket_cycles[multisocket_selector/2]) * power_millis[multisocket_selector/2])) + "mW" + " ")
            print printed_str
        print ""
        for key, data in idles.items():
            printed_str = str(data.pid) + " " + str(data.comm) + " " + str(data.bpf_selector) + " "
            for multisocket_selector in range(1, len(socket_set)*2, 2):
                if data.ts[multisocket_selector] + timeslice > tsmax:
                    i = i + float(data.time_ns[multisocket_selector])/1000000
                printed_str = ( printed_str + str(data.ts[multisocket_selector])
                    + " " + str(data.weighted_cycles[multisocket_selector])
                    + " " + str(float(data.time_ns[multisocket_selector])/1000000)
                    + "  {:.3f}".format((float(data.weighted_cycles[multisocket_selector])
                        / float(weighted_socket_cycles[multisocket_selector/2]) * power_millis[multisocket_selector/2])) + "mW" + " ")
            print printed_str
        print ""
    print "millis run: " + str(i/(timeslice/1000000000)) + " time slept last time in millis: " + str(time_to_sleep*1000)

    for key, data in conf.items():
        print str(key.value) + " " + str(data.value)
    print str(sched_switch_count) + " " + str(sched_switch_count/(multiprocessing.cpu_count()*(timeslice/1000000000)))


    if sched_switch_count/(multiprocessing.cpu_count()*(timeslice/1000000000))< 100:
        conf[ct.c_int(2)] = ct.c_uint(4000000000)
        timeslice = 4000000000
    elif sched_switch_count/(multiprocessing.cpu_count()*(timeslice/1000000000))< 200:
        conf[ct.c_int(2)] = ct.c_uint(3000000000)
        timeslice = 3000000000
    elif sched_switch_count/(multiprocessing.cpu_count()*(timeslice/1000000000))< 300:
        conf[ct.c_int(2)] = ct.c_uint(2000000000)
        timeslice = 2000000000
    else:
        conf[ct.c_int(2)] = ct.c_uint(1000000000)
        timeslice = 1000000000

    time_to_sleep = timeslice/1000000000 - (time.time() - start_time)


    s1e = rapl_sample_start[0].energy()
    s2e = rapl_sample_end[0].energy()
    diffe = rapl_diff[0].energy()
    print("")
    print("RAPL energy and power information")
    print("Socket 0: %d J - %d J = %d J ----- (power=%0.2fmW)" % (s2e, s1e, diffe, power_millis[0]))
    # print("Socket 1: %d J - %d J = %d J ----- (power=%0.2fmW)" % (s2e, s1e, diffe, power_millis[1]))
    print("")
    print("Total weighted cycles socket 0 = ", weighted_socket_cycles[0])
    # print("Total weighted cycles socket 1 = ", weighted_socket_cycles[1])
