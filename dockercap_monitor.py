from bcc import BPF, PerfType, PerfHWConfig
import multiprocessing
import ctypes as ct
import os
import time

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
                ("bpf_selector", ct.c_int),
                ("ts", ct.c_ulonglong)]

class ErrorCode(ct.Structure):
    _fields_ = [("err", ct.c_int)]

#Load BPF program
bpf_program = BPF(src_file="bpf/bpf_monitor.c", cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
# Open cycles PMC
bpf_program["cpu_cycles"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)
# get tables
processors = bpf_program.get_table("processors")
pids = bpf_program.get_table("pids")
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
                if value[2] == core_id:
                    found = True
                    value[1] = ht_id
                    coresDict[ht_id] = [ht_id, value[0], core_id, processor_id]
                    break
            if not found:
                coresDict[ht_id] = [ht_id, -1, core_id, processor_id]

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
bpf_program.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_function")
# attach error buffer
#bpf_program["err"].open_perf_buffer(print_event, page_cnt=256)

# sleep and retrieve data
while True:
    time.sleep(2)
    # print debug stuff
    #bpf_program.kprobe_poll()

    print conf[ct.c_int(0)].value
    if conf[ct.c_int(0)].value == 0:
        conf[ct.c_int(0)] = ct.c_uint(1)
        for key, data in pids.items():
            print str(data.pid) + " " + str(data.ts) + " " + str(data.comm) + " " + str(data.weighted_cycles[0]) + " " + str(data.weighted_cycles[1]) + " " + str(data.bpf_selector)
        print "\n"

    else:
        conf[ct.c_int(0)] = ct.c_uint(0)
        for key, data in pids.items():
            print str(data.pid) + " " + str(data.ts) + " " + str(data.comm) + " " + str(data.weighted_cycles[0]) + " " + str(data.weighted_cycles[1]) + " " + str(data.bpf_selector)
        print "\n"
