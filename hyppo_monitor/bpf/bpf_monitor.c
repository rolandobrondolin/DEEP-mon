#include <uapi/linux/bpf_perf_event.h>

/**
 * In the rest of the code we are going to use a selector to read and write
 * events. The idea is that while userspace is reading events
 * for selector 0 we write events using selector 1 and vice versa.
 * This process in handled by the bpf_selector variable.
 */
#define SELECTOR_DIM 2 // Use a binary selector

/**
 * Slots are array cells we use to store events following the selector idea.
 * Let's take as an example NUM_SOCKETS=2 (2 physical CPUs) and let's keep
 * SELECTOR_DIM=2 as defined above. In this case the array would have four slots
 * and will be partitioned in the following way:
 * [ CPU_0 SELECTOR_0 | CPU_0 SELECTOR_1 | CPU_1 SELECTOR_0 | CPU_1 SELECTOR_1 ]
 */
#define NUM_SLOTS NUM_SOCKETS * SELECTOR_DIM

/**
 * pid_status is used to store information about pid X
 * bpf_selector is used for the slot selection described above and is set
 * in the BPF context. PCM arrays like cycles and IR are written by BPF but
 * read and initialized from user space.
 */
struct pid_status {
        int pid;                            /**< Process ID */
        char comm[TASK_COMM_LEN];                      /**< Process name */
        u64 weighted_cycles[NUM_SLOTS];     /**< Number of weighted cycles executed by the process */
        u64 instruction_retired[NUM_SLOTS]; /**< Number of instructions executed by the process */
        u64 time_ns[NUM_SLOTS];             /**< Execution time of the process (in ns) */
        unsigned int bpf_selector;          /**< Slot selector */
        u64 ts[NUM_SLOTS];                  /**< Timestamp of the latest update */
};

/**
 * proc_topology is used to store information about the underlying topology
 * of CPUS.
 * We distinguish processors, cores (physical core) and ht/thread (soft cores).
 * Siblings cores are two soft cores residing on the same physical core.
 */
struct proc_topology {
        u64 ht_id;
        u64 sibling_id;
        u64 core_id;
        u64 processor_id;
        u64 cycles_core;
        u64 cycles_core_delta_sibling;
        u64 cycles_thread;
        u64 instruction_thread;
        u64 ts;
        int running_pid;
};

/**
 * sched_switch_args is the payload of a sched_switch tracepoint event
 * as defined in the Linux kernel.
 */
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
struct sched_process_exec_args {
        __u64 pad; // regs after 4.x?
        char filename[4];
        int pid;
        int old_pid;
};
struct sched_process_fork_args {
        __u64 pad; // regs after 4.x?
        char parent_comm[16];
        int parent_pid;
        char child_comm[16];
        int child_pid;
};
struct sched_process_exit_args {
        __u64 pad; // regs after 4.x?
        char comm[16];
        int pid;
        int prio;
};

#ifdef DEBUG
struct error_code {
        int err;
};

BPF_PERF_OUTPUT(err);
#endif

BPF_PERF_ARRAY(cycles_core, NUM_CPUS);
BPF_PERF_ARRAY(cycles_thread, NUM_CPUS);
BPF_PERF_ARRAY(instr_thread, NUM_CPUS);
BPF_HASH(processors, u64, struct proc_topology);
BPF_HASH(pids, int, struct pid_status);
BPF_HASH(idles, u64, struct pid_status);

/**
 * conf struct has 4 integer keys initialized in user space
 * 0: current bpf selector
 * 1: old bpf selector
 * 2: timeslice (dynamic window duration)
 * 3: switch count (global context switch counter). Used to compute the window size
 */
BPF_HASH(conf, int, unsigned int);

/*
 * timestamp array to store the last timestamp of a given time slot
 */
BPF_ARRAY(global_timestamps, u64, SELECTOR_DIM);


/**
 * STEP_MIN and STEP_MAX are the lower and upper bound for the duration
 * of the dynamic window (interval between two reads from user space)
 * They are expressed in nanoseconds so their range is 1-4 second.
 * BEWARE: Changing the step in userspace means invalidate the last sample
 */
#define STEP_MIN 1000000000
#define STEP_MAX 4000000000

#define HAPPY_FACTOR 11/20
#define STD_FACTOR 1


static void send_error(struct sched_switch_args *ctx, int err_code) {
#ifdef DEBUG
        struct error_code error;
        error.err = err_code;
        err.perf_submit(ctx, &error, sizeof(error));
#endif
}

static void send_perf_error(struct bpf_perf_event_data *ctx, int err_code) {
#ifdef DEBUG
        struct error_code error;
        error.err = err_code;
        err.perf_submit(ctx, &error, sizeof(error));
#endif
}

static inline int update_cycles_count(void *ctx,
        u32 old_pid, u32 bpf_selector, u32 step, u64 processor_id,
        u64 thread_cycles_sample, u64 core_cycles_sample,
        u64 instruction_retired_thread, u64 ts) {

    int ret = 0;

    // Fetch more data about processor where the sched_switch happened
    struct proc_topology topology_info;
    ret = bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));
    if(ret!= 0 || topology_info.ht_id > NUM_CPUS) {
            send_error(ctx, -4);
            return 0;
    }

    // Create the struct to hold the pid status we are going to fetch
    struct pid_status status_old;
    status_old.pid = -1;

    /**
     * Fetch the status of the exiting pid.
     * If the pid is 0 then use the idles perf_hash
     */
    if(old_pid == 0) {
            ret = bpf_probe_read(&status_old, sizeof(status_old), idles.lookup(&(processor_id)));
    } else {
            ret = bpf_probe_read(&status_old, sizeof(status_old), pids.lookup(&(old_pid)));
    }

    // Retrieving information of the sibling processor
    u64 sibling_id = topology_info.sibling_id;
    struct proc_topology sibling_info;
    ret = bpf_probe_read(&sibling_info, sizeof(sibling_info), processors.lookup(&(sibling_id)));

    if(ret != 0) {
        // Wrong info on topology, do nothing
        send_error(ctx, 3);
        return 0;
    }

    /**
     * Instead of adding stuff directly, given that we don't have
     * the measure of the sibling thread cycles, we are summing up
     * the information on our side to the core cycles of the sibling
     */
    // Update sibling process info
    if(sibling_info.running_pid > 0 && old_pid > 0 && core_cycles_sample > sibling_info.cycles_core) {
            sibling_info.cycles_core_delta_sibling += core_cycles_sample - sibling_info.cycles_core;
    }
    sibling_info.cycles_core = core_cycles_sample;
    processors.update(&sibling_id, &sibling_info);

    /**
     * Get back to our pid and our processor
     * Update the data for proc_topology and pid info
     * Take the ts marking the beginning of execution of the exiting pid
     */
    u64 last_ts_pid_in = 0;
    //trick the compiler with loop unrolling
    #pragma clang loop unroll(full)
    for(int array_index = 0; array_index<NUM_SLOTS; array_index++) {
            if(array_index == status_old.bpf_selector + SELECTOR_DIM * topology_info.processor_id) {
                    last_ts_pid_in = status_old.ts[array_index];
            }
    }

    /**
     * If we have exceeded the duration of the dynamic window (change
     * in the bpf_selector or current ts greater than the end of
     * the window) we need to update the selector and reset PCM counters
     */
    if(status_old.bpf_selector != bpf_selector || last_ts_pid_in + step < ts) {
            status_old.bpf_selector = bpf_selector;
            //trick the compiler with loop unrolling
            #pragma clang loop unroll(full)
            for(int array_index = 0; array_index<NUM_SLOTS; array_index++) {
                    if(array_index % SELECTOR_DIM == bpf_selector) {
                            status_old.weighted_cycles[array_index] = 0;
                            status_old.instruction_retired[array_index] = 0;
                            status_old.time_ns[array_index] = 0;
                    }
            }
    }


    /**
     * Start to account PCM values for the exiting pid
     */
    u64 old_thread_cycles = thread_cycles_sample;
    u64 cycles_core_delta_sibling = 0;
    u64 old_time = ts;
    u64 old_instruction_retired = instruction_retired_thread;
    if (topology_info.ts > 0) {
            old_time = topology_info.ts;
            old_thread_cycles = topology_info.cycles_thread;
            cycles_core_delta_sibling = topology_info.cycles_core_delta_sibling;
            old_instruction_retired = topology_info.instruction_thread;
            if (old_pid > 0 && sibling_info.running_pid > 0 && core_cycles_sample > topology_info.cycles_core) {
                    cycles_core_delta_sibling += core_cycles_sample - topology_info.cycles_core;
            }
    }

    //trick the compiler with loop unrolling
    // update measurements for our pid
    #pragma clang loop unroll(full)
    for(int array_index = 0; array_index<NUM_SLOTS; array_index++) {
            if(array_index == status_old.bpf_selector + SELECTOR_DIM * topology_info.processor_id) {
                    //discard sample if cycles counter did overflow
                    if (thread_cycles_sample > old_thread_cycles){
                            u64 cycle1 = thread_cycles_sample - old_thread_cycles;
                            u64 cycle_overlap = cycles_core_delta_sibling;
                            u64 cycle_non_overlap = cycle1 > cycles_core_delta_sibling ? cycle1 - cycles_core_delta_sibling : 0;
                            status_old.weighted_cycles[array_index] += cycle_non_overlap + cycle_overlap*HAPPY_FACTOR;
                    } else {
                            send_error(ctx, old_pid);
                    }
                    if (instruction_retired_thread > old_instruction_retired) {
                            status_old.instruction_retired[array_index] = instruction_retired_thread - old_instruction_retired;
                    } else {
                            send_error(ctx, old_pid);
                    }
                    status_old.time_ns[array_index] += ts - old_time;
                    status_old.ts[array_index] = ts;
                    if(old_pid == 0) {
                            idles.update(&processor_id, &status_old);
                    } else {
                            pids.update(&old_pid, &status_old);
                    }
            }
    }
    return 0;
}

int trace_switch(struct sched_switch_args *ctx) {

        // Keys for the conf hash
        int selector_key = 0;
        int old_selector_key = 1;
        int step_key = 2;
        int switch_count_key = 3;

        // Slot iterator for the selector
        int array_index = 0;

        // Binary selector to avoid event overwriting
        unsigned int bpf_selector = 0;
        int ret = 0;
        ret = bpf_probe_read(&bpf_selector, sizeof(bpf_selector), conf.lookup(&selector_key));
        // If selector is not in place correctly, signal debug error and stop tracing routine
        if (ret!= 0 || bpf_selector > 1) {
                send_error(ctx, -1);
                return 0;
        }

        // Retrieve general switch count
        unsigned int switch_count = 0;
        ret = 0;
        ret = bpf_probe_read(&switch_count, sizeof(switch_count), conf.lookup(&switch_count_key));

        /**
         * Retrieve old selector to update switch count correctly
         * If the current selector is still active increase the switch count
         * otherwise reset the count and update the current selector
         */
        unsigned int old_bpf_selector = 0;
        ret = 0;
        ret = bpf_probe_read(&old_bpf_selector, sizeof(old_bpf_selector), conf.lookup(&old_selector_key));
        if (ret!= 0 || old_bpf_selector > 1) {
                send_error(ctx, -2);
                return 0;
        } else if(old_bpf_selector != bpf_selector) {
                switch_count = 1;
                conf.update(&old_selector_key, &bpf_selector);
        } else {
                switch_count++;
        }
        conf.update(&switch_count_key, &switch_count);

        /**
         * Retrieve sampling step (dynamic window)
         * We need this because later on we check the timestamp of the
         * context switch, if it's higher than ts_begin_window + step
         * we need to account the current pcm in the next time window (so in
         * another bpf selector w.r.t. to the current one)
         * BEWARE: increasing the step in userspace means that the next
         *         sample is invalid. Reducing the step in userspace is not
         *         an issue, it discards data that has already been collected
         */
        unsigned int step = 1000000000;
        ret = bpf_probe_read(&step, sizeof(step), conf.lookup(&step_key));
        if (ret!= 0 || step < STEP_MIN || step > STEP_MAX) {
                send_error(ctx, -3);
                return 0;
        }

        /**
         * Get the id of the processor where the sched_switch happened.
         * Collect cycles and IR samples from perf arrays.
         * Save the timestamp and store the exiting pid
         */
        u64 processor_id = bpf_get_smp_processor_id();
        u64 thread_cycles_sample = cycles_thread.perf_read(processor_id);
        u64 core_cycles_sample = cycles_core.perf_read(processor_id);
        u64 instruction_retired_thread = instr_thread.perf_read(processor_id);
        u64 ts = bpf_ktime_get_ns();
        int current_pid = ctx->prev_pid;

        update_cycles_count(ctx, current_pid, bpf_selector, step, processor_id, thread_cycles_sample, core_cycles_sample, instruction_retired_thread, ts);

        // Fetch more data about processor where the sched_switch happened
        ret = 0;
        struct proc_topology topology_info;
        ret = bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));
        if(ret!= 0 || topology_info.ht_id > NUM_CPUS) {
                send_error(ctx, -4);
                return 0;
        }

        //
        // handle new scheduled process
        //
        int new_pid = ctx->next_pid;
        struct pid_status status_new;
        if(new_pid == 0) {
                ret = bpf_probe_read(&status_new, sizeof(status_new), idles.lookup(&(processor_id)));
        } else {
                ret = bpf_probe_read(&status_new, sizeof(status_new), pids.lookup(&(new_pid)));
        }
        //If no status for PID, then create one, otherwise update selector
        if(ret) {
                bpf_probe_read(&(status_new.comm), sizeof(status_new.comm), ctx->next_comm);
                #pragma clang loop unroll(full)
                for(array_index = 0; array_index<NUM_SLOTS; array_index++) {
                        status_new.ts[array_index] = ts;
                        status_new.weighted_cycles[array_index] = 0;
                        status_new.instruction_retired[array_index] = 0;
                        status_new.time_ns[array_index] = 0;
                }
                status_new.pid = new_pid;
                status_new.bpf_selector = bpf_selector;
                if(new_pid == 0) {
                        idles.insert(&processor_id, &status_new);
                } else {
                        pids.insert(&new_pid, &status_new);
                }
        }
        //add info on new running pid into processors table
        topology_info.running_pid = new_pid;
        topology_info.cycles_thread = thread_cycles_sample;
        topology_info.cycles_core_delta_sibling = 0;
        topology_info.cycles_core = core_cycles_sample;
        topology_info.instruction_thread = instruction_retired_thread;
        topology_info.ts = ts;
        processors.update(&processor_id, &topology_info);

        global_timestamps.update(&bpf_selector, &ts);

        return 0;

}

int trace_exit(struct sched_process_exit_args *ctx) {

        char comm[16];
        bpf_probe_read(&(comm), sizeof(comm), ctx->comm);
        int pid = ctx->pid;
        u64 ts = bpf_ktime_get_ns();
        u64 processor_id = bpf_get_smp_processor_id();

        //remove the pid from the table if there
        pids.delete(&pid);

        struct proc_topology topology_info;
        bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));

        topology_info.running_pid = 0;
        topology_info.cycles_thread = cycles_thread.perf_read(processor_id);
        topology_info.cycles_core = cycles_core.perf_read(processor_id);
        topology_info.instruction_thread = instr_thread.perf_read(processor_id);
        topology_info.cycles_core_delta_sibling = 0;
        topology_info.ts = ts;

        processors.update(&processor_id, &topology_info);

        return 0;
}

int timed_trace(struct bpf_perf_event_data *perf_ctx) {

        // Keys for the conf hash
        int selector_key = 0;
        int old_selector_key = 1;
        int step_key = 2;
        int switch_count_key = 3;

        // Slot iterator for the selector
        int array_index = 0;

        // Binary selector to avoid event overwriting
        unsigned int bpf_selector = 0;
        int ret = 0;
        ret = bpf_probe_read(&bpf_selector, sizeof(bpf_selector), conf.lookup(&selector_key));
        // If selector is not in place correctly, signal debug error and stop tracing routine
        if (ret!= 0 || bpf_selector > 1) {
                send_perf_error(perf_ctx, -1);
                return 0;
        }


        // Retrieve general switch count
        unsigned int switch_count = 0;
        ret = 0;
        ret = bpf_probe_read(&switch_count, sizeof(switch_count), conf.lookup(&switch_count_key));

        /**
         * Retrieve old selector to update switch count correctly
         * If the current selector is still active increase the switch count
         * otherwise reset the count and update the current selector
         */
        unsigned int old_bpf_selector = 0;
        ret = 0;
        ret = bpf_probe_read(&old_bpf_selector, sizeof(old_bpf_selector), conf.lookup(&old_selector_key));
        if (ret!= 0 || old_bpf_selector > 1) {
                send_perf_error(perf_ctx, -2);
                return 0;
        } else if(old_bpf_selector != bpf_selector) {
                switch_count = 1;
                conf.update(&old_selector_key, &bpf_selector);
        } else {
                switch_count++;
        }
        conf.update(&switch_count_key, &switch_count);

        /**
         * Retrieve sampling step (dynamic window)
         * We need this because later on we check the timestamp of the
         * context switch, if it's higher than ts_begin_window + step
         * we need to account the current pcm in the next time window (so in
         * another bpf selector w.r.t. to the current one)
         * BEWARE: increasing the step in userspace means that the next
         *         sample is invalid. Reducing the step in userspace is not
         *         an issue, it discards data that has already been collected
         */
        unsigned int step = 1000000000;
        ret = bpf_probe_read(&step, sizeof(step), conf.lookup(&step_key));
        if (ret!= 0 || step < STEP_MIN || step > STEP_MAX) {
                send_perf_error(perf_ctx, -3);
                return 0;
        }

        u32 current_pid = bpf_get_current_pid_tgid();

        /* Read the values of the performance counters to update the data
         * inside our hashmap
         */
        u64 processor_id = bpf_get_smp_processor_id();
        u64 thread_cycles_sample = cycles_thread.perf_read(processor_id);
        u64 core_cycles_sample = cycles_core.perf_read(processor_id);
        u64 instruction_retired_thread = instr_thread.perf_read(processor_id);
        u64 ts = bpf_ktime_get_ns();

        update_cycles_count(perf_ctx, current_pid, bpf_selector, step, processor_id, thread_cycles_sample, core_cycles_sample, instruction_retired_thread, ts);


        // Fetch more data about processor we are currently dealing with
        ret = 0;
        struct proc_topology topology_info;
        ret = bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));
        if(ret!= 0 || topology_info.ht_id > NUM_CPUS) {
                send_perf_error(perf_ctx, -4);
                return 0;
        }

        //update topology info since we are forcing the update with a timer
        topology_info.running_pid = current_pid;
        topology_info.cycles_thread = thread_cycles_sample;
        topology_info.cycles_core_delta_sibling = 0;
        topology_info.cycles_core = core_cycles_sample;
        topology_info.instruction_thread = instruction_retired_thread;
        topology_info.ts = ts;
        processors.update(&processor_id, &topology_info);

        global_timestamps.update(&bpf_selector, &ts);

        return 0;
}
