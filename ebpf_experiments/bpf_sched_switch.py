from bcc import BPF
import ctypes as ct
import os
import time

bpf_tracer = BPF(src_file="bpf_sched_switch.c")
bpf_tracer.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_function")

# define output data structure in Python
TASK_COMM_LEN = 16    # linux/sched.h

class Data(ct.Structure):
    _fields_ = [("ts", ct.c_ulonglong),
    			("old_pid", ct.c_int),
    			("new_pid", ct.c_int),
                ("processor_id", ct.c_ulonglong),
                ("old_comm", ct.c_char * TASK_COMM_LEN),
                ("new_comm", ct.c_char * TASK_COMM_LEN)]

# header
print("%-18s %-16s %-6s %-6s %-6s %s" % ("TIME(s)", "COMM", "OLD PID", "NEW PID", "PROC_ID", "NEW COMM"))

start = 0
def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    #print("%-18.9f %-16s %-6d %-6d %-6d %s" % (time_s, event.old_comm, event.old_pid, event.new_pid, event.processor_id, event.new_comm))
    print str(time_s) + " " + event.old_comm + " " + str(event.old_pid) + " " + event.new_comm + " " + str(event.new_pid) + " " + str(event.processor_id)

# loop with callback to print_event
bpf_tracer["events"].open_perf_buffer(print_event)

while 1:
    bpf_tracer.kprobe_poll()