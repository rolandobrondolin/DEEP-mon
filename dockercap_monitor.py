from bcc import BPF, PerfType, PerfHWConfig
import multiprocessing
import ctypes as ct
import os
import time

debug = False
TASK_COMM_LEN = 16

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
                ("weighted_cycles", ct.c_ulonglong * 2),
                ("time_ns", ct.c_ulonglong * 2),
                ("bpf_selector", ct.c_int),
                ("ts", ct.c_ulonglong * 2)]

class ErrorCode(ct.Structure):
    _fields_ = [("err", ct.c_int)]

#Load BPF program
bpf_program = BPF(src_file="bpf/bpf_monitor.c", cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
# Open cycles PMC
bpf_program["cpu_cycles"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)
# get tables
processors = bpf_program.get_table("processors")
pids = bpf_program.get_table("pids")
idles = bpf_program.get_table("idles")
conf = bpf_program.get_table("conf")
# set default bpf_selector
conf[ct.c_int(0)] = ct.c_uint(1)

# parse /proc/cpuinfo to obtain processor topology
ht_id = 0
sibling_id = 0
core_id = 0
processor_id = 0

coresDict = {} #core elem is organized as ht_id, sibling_id, core_id, processor_id

with open('/proc/cpuinfo') as f:
    for line in f:
        sp = line.split(" ")
        if "processor\t" in sp[0]:
            ht_id = int(sp[1])
        if "physical" in sp[0] and "id\t" in sp[1]:
            processor_id = int(sp[2])
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
time_to_sleep = 1
# sleep and retrieve data
while True:
    time.sleep(time_to_sleep)
    start_time = time.time()
    # print debug stuff
    if debug == True:
        bpf_program.kprobe_poll()
    i = 0.0
    print conf[ct.c_int(0)].value
    if conf[ct.c_int(0)].value == 0:
        conf[ct.c_int(0)] = ct.c_uint(1)

        tsmax = 0
        for key, data in pids.items():
            if data.ts[0] > tsmax:
                tsmax = data.ts[0]
        for key, data in idles.items():
            if data.ts[0] > tsmax:
                tsmax = data.ts[0]

        for key, data in pids.items():
            if data.ts[0] + 2000000000 > tsmax:
                i = i + float(data.time_ns[0])/1000000
                print str(data.pid) + " " + str(data.ts[0]) + " " + str(data.comm) + " " + str(data.weighted_cycles[0]) + " " + str(float(data.time_ns[0])/1000000) + " " + str(data.bpf_selector)
        print ""
        for key, data in idles.items():
            if data.ts[0] + 2000000000 > tsmax:
                i = i + float(data.time_ns[0])/1000000
                print str(key.value) + " " + str(data.ts[0]) + " " + str(data.comm) + " " + str(data.weighted_cycles[0]) + " " + str(float(data.time_ns[0])/1000000) + " " + str(data.bpf_selector)
        print "\n"

    else:
        conf[ct.c_int(0)] = ct.c_uint(0)
        tsmax = 0
        for key, data in pids.items():
            if data.ts[1] > tsmax:
                tsmax = data.ts[1]
        for key, data in idles.items():
            if data.ts[1] > tsmax:
                tsmax = data.ts[1]

        for key, data in pids.items():
            if data.ts[1] + 2000000000 > tsmax:
                i = i + float(data.time_ns[1])/1000000
                print str(data.pid) + " " + str(data.ts[1]) + " " + str(data.comm) + " " + str(data.weighted_cycles[1]) + " " + str(float(data.time_ns[1])/1000000) + " " + str(data.bpf_selector)
        print ""
        for key, data in idles.items():
            if data.ts[1] + 2000000000 > tsmax:
                i = i + float(data.time_ns[1])/1000000
                print str(key.value) + " " + str(data.ts[1]) + " " + str(data.comm) + " " + str(data.weighted_cycles[1]) + " " + str(float(data.time_ns[1])/1000000) + " " + str(data.bpf_selector)
        print "\n"
    print "millis run: " + str(i) + " time slept last time in millis: " + str(time_to_sleep*1000)
    time_to_sleep = 1 - (time.time() - start_time)
