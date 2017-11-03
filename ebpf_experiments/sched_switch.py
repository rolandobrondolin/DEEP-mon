from bcc import BPF, PerfType, PerfHWConfig
import argparse
import multiprocessing

parser = argparse.ArgumentParser(description='Track context switches')
parser.add_argument("-p", "--pid", type=int,
    help="id of the process to trace", required=True)
args = parser.parse_args()
pid = args.pid

# load BPF program
text = """
BPF_PERF_ARRAY(cpu_cycles, NUM_CPUS);
TRACEPOINT_PROBE(sched, sched_switch) {{

    /**
    *   args is from /sys/kernel/debug/tracing/events/sched/sched_switch/format
    *   to easly lookup the args struct use: `tplist -v sched:sched_switch`
    */

    if (args->next_pid == {}) {{
        u64 cpu_cycles_count = cpu_cycles.perf_read(CUR_CPU_IDENTIFIER);
        bpf_trace_printk("Switching... next PID: %d, CPU cycles: %llu\\n",
            args->next_pid, cpu_cycles_count);
    }}
    return 0;
}};
""".format(pid)

b = BPF(text=text, cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
b["cpu_cycles"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)

# header
print("%-18s %-16s %-6s %-4s %s" % ("TIME(s)", "COMM", "PID", "CPU", "MSG"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %-4d %s" % (ts, task, pid, cpu, msg))
