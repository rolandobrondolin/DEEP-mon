from bcc import BPF, PerfType, PerfHWConfig
import multiprocessing
import ctypes as ct
import os
import time

bpf_tracer = BPF(src_file="bpf_sched_switch.c", cflags=[
                 "-DNUM_CPUS=%d" % multiprocessing.cpu_count(), "-DFILTER_PID=%d" % os.getpid()])
bpf_tracer.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_function")
#bpf_tracer["cpu_cycles"].open_perf_event(
#    PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)
bpf_tracer["core_cycles"].open_perf_event(4, int("72003c",16))
bpf_tracer["thread_cycles"].open_perf_event(4, int("52003c",16))

# define output data structure in Python
TASK_COMM_LEN = 16    # linux/sched.h


class Data(ct.Structure):
    _fields_ = [("ts", ct.c_ulonglong),
                ("old_pid", ct.c_int),
                ("new_pid", ct.c_int),
                ("processor_id", ct.c_ulonglong),
                ("old_comm", ct.c_char * TASK_COMM_LEN),
                ("new_comm", ct.c_char * TASK_COMM_LEN),
                ("cycles", ct.c_ulonglong * multiprocessing.cpu_count())]


# header
print("%-18s %-16s %-6s %-6s %-6s %s" %
      ("TIME(s)", "COMM", "OLD PID", "NEW PID", "PROC_ID", "NEW COMM"))

start = 0L
end = 0L
elapsed = 0L
count = 0L


def print_event(cpu, data, size):
    global start
    global end
    global count
    global elapsed
    event = ct.cast(data, ct.POINTER(Data)).contents
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    count = count + 1
    elapsed = time_s
    end = event.ts
    #print("%-18.9f %-16s %-6d %-6d %-6d %s" % (time_s, event.old_comm, event.old_pid, event.new_pid, event.processor_id, event.new_comm))
    to_be_printed = str(time_s) + " " + event.old_comm + " " + str(event.old_pid) + " " + event.new_comm + " " + str(event.new_pid) + " " + str(event.processor_id) + " "
    for i in range(0,multiprocessing.cpu_count()):
        to_be_printed = to_be_printed + str(event.cycles[i]) + " "
    print to_be_printed

# loop with callback to print_event
bpf_tracer["events"].open_perf_buffer(print_event, page_cnt=256)

try:
    while True:
        bpf_tracer.kprobe_poll()
        time.sleep(0.1)
except(KeyboardInterrupt):
    print(str(count) + " " + str(start) + " " + str(end) + " " + str(elapsed))
