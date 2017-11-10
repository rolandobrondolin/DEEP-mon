#include <linux/sched.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/kernel.h>

//#define SEC(NAME) __attribute__((section(NAME), used))

BPF_PERF_OUTPUT(events);
BPF_PERF_ARRAY(cpu_cycles, NUM_CPUS);

// define output data structure in C
struct data_t {
        u64 ts;
        int old_pid;
        int new_pid;
        u64 processor_id;
        char old_comm[16];
        char new_comm[16];
        u64 cycles;
};

struct sched_switch_args {
        __u64 pad; // regs after 4.x?
        char prev_comm[16];
        int prev_pid;
        int prev_prio;
        long long prev_state;
        char next_comm[16];
        int next_pid;
        int next_prio;
};

//SEC("tracepoint/sched/sched_switch")
int trace_function(struct sched_switch_args *ctx) {

        if(ctx->prev_pid != FILTER_PID && ctx->next_pid != FILTER_PID) {
                struct data_t data = {};
                data.ts = bpf_ktime_get_ns();
                data.old_pid = ctx->prev_pid;
                data.new_pid = ctx->next_pid;
                data.processor_id = bpf_get_smp_processor_id();
                bpf_probe_read(&(data.old_comm), sizeof(data.old_comm), ctx->prev_comm);
                bpf_probe_read(&(data.new_comm), sizeof(data.new_comm), ctx->next_comm);

                data.cycles = cpu_cycles.perf_read(data.processor_id);
                events.perf_submit(ctx, &data, sizeof(data));
        }

        return 0;
}


// TRACEPOINT_PROBE(sched, sched_switch) {
//     // args is from /sys/kernel/debug/tracing/events/sched/sched_switch/format
//  struct data_t data = {};
//  data.ts = bpf_ktime_get_ns();
//  data.old_pid = args->prev_pid;
//  data.new_pid = args->next_pid;
//  data.processor_id = bpf_get_smp_processor_id();
//  //strcpy(data.old_comm, args->prev_comm);
//  //strcpy(data.new_comm, args->next_comm);
//  //data.old_comm[] = (args->prev_comm);
//  //data.new_comm[] = (args->next_comm);
//  //sprintf(data.old_comm, "%s", args->prev_comm);
//  //sprintf(data.new_comm, "%s", args->next_comm);
//  bpf_probe_read(&(data.old_comm), sizeof(data.old_comm), args->prev_comm);
//  bpf_probe_read(&(data.new_comm), sizeof(data.new_comm), args->next_comm);
//  //events.perf_submit(args, &data, sizeof(data));
//  bpf_trace_printk("%s %llu\n", data.old_comm, data.old_pid);
//  return 0;
// };
