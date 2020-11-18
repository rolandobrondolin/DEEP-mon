/*
    DEEP-mon
    Copyright (C) 2020  Brondolin Rolando

    This file is part of DEEP-mon

    DEEP-mon is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DEEP-mon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
        int tgid;
        char comm[TASK_COMM_LEN];           /**< Process name */
        u64 weighted_cycles[NUM_SLOTS];     /**< Number of weighted cycles executed by the process */
        u64 cycles[SELECTOR_DIM];              /**< Number of unhalted core cycles executed by the process */
        u64 instruction_retired[SELECTOR_DIM]; /**< Number of instructions executed by the process */
        u64 cache_misses[SELECTOR_DIM];        /**< Number of Last Level Cache misses executed by the process */
        u64 cache_refs[SELECTOR_DIM];        /**< Number of Last Level Cache references executed by the process */
        u64 time_ns[SELECTOR_DIM];             /**< Execution time of the process (in ns) */
        unsigned int bpf_selector;          /**< Slot selector */
        u64 ts[SELECTOR_DIM];                  /**< Timestamp of the latest update */
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
        u64 cache_misses;
        u64 cache_refs;
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

#ifdef PERFORMANCE_COUNTERS
BPF_PERF_ARRAY(cycles_core, NUM_CPUS);
BPF_PERF_ARRAY(cycles_thread, NUM_CPUS);
BPF_PERF_ARRAY(instr_thread, NUM_CPUS);
BPF_PERF_ARRAY(cache_misses, NUM_CPUS);
BPF_PERF_ARRAY(cache_refs, NUM_CPUS);
#endif
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
#define BPF_SELECTOR_INDEX 0
#define BPF_SELECTOR_INDEX_OLD 1
#define BPF_TIMESLICE 2
#define BPF_SWITCH_COUNT 3
BPF_ARRAY(conf, u32, 4);

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

/*
 * Errors code for userspace debug
 */
#define BPF_PROCEED_WITH_DEBUG_MODE -1
#define BPF_SELECTOR_NOT_IN_PLACE -2
#define OLD_BPF_SELECTOR_NOT_IN_PLACE -3
#define TIMESTEP_NOT_IN_PLACE -4
#define CORRUPTED_TOPOLOGY_MAP -5
#define WRONG_SIBLING_TOPOLOGY_MAP -6
#define THREAD_MIGRATED_UNEXPECTEDLY -7


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
        int old_pid, u32 bpf_selector, u32 step, u64 processor_id,
#ifdef PERFORMANCE_COUNTERS
        u64 thread_cycles_sample, u64 core_cycles_sample,
        u64 instruction_retired_thread, u64 cache_misses_thread,
        u64 cache_refs_thread,
#endif
        u64 ts) {

    int ret = 0;

    // Fetch more data about processor where the sched_switch happened
    struct proc_topology topology_info;
    ret = bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));
    if(ret!= 0 || topology_info.ht_id > NUM_CPUS) {
            send_error(ctx, CORRUPTED_TOPOLOGY_MAP);
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

    if(ret != 0) {
        // no data for this thread, for now do not account data
        return 0;
    }

    if (topology_info.running_pid != status_old.pid) {
        // we have some issues
        send_error(ctx, THREAD_MIGRATED_UNEXPECTEDLY);
        return 0;
    }

#ifdef PERFORMANCE_COUNTERS
    // Retrieving information of the sibling processor
    u64 sibling_id = topology_info.sibling_id;
    struct proc_topology sibling_info;
    ret = bpf_probe_read(&sibling_info, sizeof(sibling_info), processors.lookup(&(sibling_id)));

    if(ret != 0) {
        // Wrong info on topology, do nothing
        send_error(ctx, WRONG_SIBLING_TOPOLOGY_MAP);
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
#endif
    /**
     * Get back to our pid and our processor
     * Update the data for proc_topology and pid info
     * Take the ts marking the beginning of execution of the exiting pid
     */
    u64 last_ts_pid_in = 0;
    //trick the compiler with loop unrolling
    #pragma clang loop unroll(full)
    for(int array_index = 0; array_index<SELECTOR_DIM; array_index++) {
            if(array_index == status_old.bpf_selector) {
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
#ifdef PERFORMANCE_COUNTERS
            //trick the compiler with loop unrolling
            #pragma clang loop unroll(full)
            for(int array_index = 0; array_index<NUM_SLOTS; array_index++) {
                    if(array_index % SELECTOR_DIM == bpf_selector) {
                            status_old.weighted_cycles[array_index] = 0;
                    }
            }
#endif
            #pragma clang loop unroll(full)
            for(int array_index = 0; array_index < SELECTOR_DIM; array_index++) {
                    if(array_index == bpf_selector) {
#ifdef PERFORMANCE_COUNTERS
                            status_old.cycles[array_index] = 0;
                            status_old.instruction_retired[array_index] = 0;
                            status_old.cache_misses[array_index] = 0;
                            status_old.cache_refs[array_index] = 0;
#endif
                            status_old.time_ns[array_index] = 0;
                    }
            }
    }

    /**
     * Start to account PCM values for the exiting pid
     */
    // u64 old_thread_cycles = thread_cycles_sample;
    // u64 cycles_core_delta_sibling = 0;
    // u64 old_time = ts;
    // u64 old_instruction_retired = instruction_retired_thread;
    // u64 old_cache_misses = cache_misses_thread;
    // u64 old_cache_refs = cache_refs_thread;
    // if (topology_info.ts > 0) {
    //         old_time = topology_info.ts;
    //         old_thread_cycles = topology_info.cycles_thread;
    //         cycles_core_delta_sibling = topology_info.cycles_core_delta_sibling;
    //         old_instruction_retired = topology_info.instruction_thread;
    //         old_cache_misses = topology_info.cache_misses;
    //         old_cache_refs = topology_info.cache_refs;
    //         //update the last slice of concurrent execution inside two sibling hyperthreads
    //         if (old_pid > 0 && sibling_info.running_pid > 0 && core_cycles_sample > topology_info.cycles_core) {
    //                 cycles_core_delta_sibling += core_cycles_sample - topology_info.cycles_core;
    //         }
    // }

    if (topology_info.ts > 0) {
            // update per process measurements (aka IR, cache misses, cycles not weighted)
            #pragma clang loop unroll(full)
            for(int array_index = 0; array_index<SELECTOR_DIM; array_index++) {
                    if(array_index == status_old.bpf_selector){
#ifdef PERFORMANCE_COUNTERS
                            if (instruction_retired_thread >= topology_info.instruction_thread) {
                                    status_old.instruction_retired[array_index] += instruction_retired_thread - topology_info.instruction_thread;
                            } else {
                                    send_error(ctx, old_pid);
                            }
                            if (cache_misses_thread >= topology_info.cache_misses) {
                                    status_old.cache_misses[array_index] += cache_misses_thread - topology_info.cache_misses;
                            } else {
                                    send_error(ctx, old_pid);
                            }
                            if (cache_refs_thread >= topology_info.cache_refs) {
                                    status_old.cache_refs[array_index] += cache_refs_thread - topology_info.cache_refs;
                            } else {
                                    send_error(ctx, old_pid);
                            }
                            if (thread_cycles_sample >= topology_info.cycles_thread){
                                    status_old.cycles[array_index] += thread_cycles_sample - topology_info.cycles_thread;
                            } else {
                                    send_error(ctx, old_pid);
                            }
#endif
                            status_old.time_ns[array_index] += ts - topology_info.ts;
                            status_old.ts[array_index] = ts;
                    }
            }
    }

#ifdef PERFORMANCE_COUNTERS
    // trick the compiler with loop unrolling
    // update weighted cycles for our pid
    if (topology_info.ts > 0) {
            #pragma clang loop unroll(full)
            for(int array_index = 0; array_index<NUM_SLOTS; array_index++) {
                    if(array_index == status_old.bpf_selector + SELECTOR_DIM * topology_info.processor_id) {
                            //discard sample if cycles counter did overflow
                            if (thread_cycles_sample > topology_info.cycles_thread){
                                    u64 cycle1 = thread_cycles_sample - topology_info.cycles_thread;
                                    u64 cycle_overlap = topology_info.cycles_core_delta_sibling;
                                    u64 cycle_non_overlap = cycle1 > topology_info.cycles_core_delta_sibling ? cycle1 - topology_info.cycles_core_delta_sibling : 0;
                                    status_old.weighted_cycles[array_index] += cycle_non_overlap + cycle_overlap*HAPPY_FACTOR;
                            } else {
                                    send_error(ctx, old_pid);
                            }
                    }
            }
    }
#endif
    // update the pid status in our hashmap
    if(old_pid == 0) {
            status_old.tgid = bpf_get_current_pid_tgid() >> 32;
            idles.update(&processor_id, &status_old);
    } else {
            status_old.tgid = bpf_get_current_pid_tgid() >> 32;
            pids.update(&old_pid, &status_old);
    }

    return 0;
}

int trace_switch(struct sched_switch_args *ctx) {

        // Keys for the conf hash
        int selector_key = BPF_SELECTOR_INDEX;
        int old_selector_key = BPF_SELECTOR_INDEX_OLD;
        int step_key = BPF_TIMESLICE;
        int switch_count_key = BPF_SWITCH_COUNT;

        // Slot iterator for the selector
        int array_index = 0;

        // Binary selector to avoid event overwriting
        unsigned int bpf_selector = 0;
        int ret = 0;
        ret = bpf_probe_read(&bpf_selector, sizeof(bpf_selector), conf.lookup(&selector_key));
        // If selector is not in place correctly, signal debug error and stop tracing routine
        if (ret!= 0 || bpf_selector > 1) {
                send_error(ctx, BPF_SELECTOR_NOT_IN_PLACE);
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
                send_error(ctx, OLD_BPF_SELECTOR_NOT_IN_PLACE);
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
                send_error(ctx, TIMESTEP_NOT_IN_PLACE);
                return 0;
        }

        /**
         * Get the id of the processor where the sched_switch happened.
         * Collect cycles and IR samples from perf arrays.
         * Save the timestamp and store the exiting pid
         */
        u64 processor_id = bpf_get_smp_processor_id();
#ifdef PERFORMANCE_COUNTERS
        u64 thread_cycles_sample = cycles_thread.perf_read(processor_id);
        u64 core_cycles_sample = cycles_core.perf_read(processor_id);
        u64 instruction_retired_thread = instr_thread.perf_read(processor_id);
        u64 cache_misses_thread = cache_misses.perf_read(processor_id);
        u64 cache_refs_thread = cache_refs.perf_read(processor_id);
#endif
        u64 ts = bpf_ktime_get_ns();
        int current_pid = ctx->prev_pid;

        if (ret == 0) {
#ifdef PERFORMANCE_COUNTERS
                update_cycles_count(ctx, current_pid, bpf_selector, step, processor_id, thread_cycles_sample, core_cycles_sample, instruction_retired_thread, cache_misses_thread, cache_refs_thread, ts);
#else
                update_cycles_count(ctx, current_pid, bpf_selector, step, processor_id, ts);
#endif
        }

        // Fetch more data about processor where the sched_switch happened
        ret = 0;
        struct proc_topology topology_info;
        ret = bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));
        if(ret!= 0 || topology_info.ht_id > NUM_CPUS) {
                send_error(ctx, CORRUPTED_TOPOLOGY_MAP);
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
                        status_new.weighted_cycles[array_index] = 0;
                }
                #pragma clang loop unroll(full)
                for(array_index = 0; array_index<SELECTOR_DIM; array_index++) {
                        status_new.ts[array_index] = ts;
                        status_new.time_ns[array_index] = 0;
#ifdef PERFORMANCE_COUNTERS
                        status_new.cycles[array_index] = 0;
                        status_new.instruction_retired[array_index] = 0;
                        status_new.cache_misses[array_index] = 0;
                        status_new.cache_refs[array_index] = 0;
#endif
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
        topology_info.ts = ts;
#ifdef PERFORMANCE_COUNTERS
        topology_info.cycles_thread = thread_cycles_sample;
        topology_info.cycles_core_delta_sibling = 0;
        topology_info.cycles_core = core_cycles_sample;
        topology_info.instruction_thread = instruction_retired_thread;
        topology_info.cache_misses = cache_misses_thread;
        topology_info.cache_refs = cache_refs_thread;
#endif
        processors.update(&processor_id, &topology_info);

        global_timestamps.update(&bpf_selector, &ts);

        return 0;

}

int trace_exit(struct sched_process_exit_args *ctx) {

        // // Keys for the conf hash
        // int selector_key = BPF_SELECTOR_INDEX;
        // int old_selector_key = BPF_SELECTOR_INDEX_OLD;
        // int step_key = BPF_TIMESLICE;
        // int switch_count_key = BPF_SWITCH_COUNT;
        //
        //
        // // Binary selector to avoid event overwriting
        // unsigned int bpf_selector = 0;
        // int ret = 0;
        // ret = bpf_probe_read(&bpf_selector, sizeof(bpf_selector), conf.lookup(&selector_key));
        // // If selector is not in place correctly, signal debug error and stop tracing routine
        // if (ret!= 0 || bpf_selector > 1) {
        //         //send_error(ctx, BPF_SELECTOR_NOT_IN_PLACE);
        //         return 0;
        // }
        //
        // unsigned int step = 1000000000;
        // ret = bpf_probe_read(&step, sizeof(step), conf.lookup(&step_key));
        // if (ret!= 0 || step < STEP_MIN || step > STEP_MAX) {
        //         //send_error(ctx, TIMESTEP_NOT_IN_PLACE);
        //         return 0;
        // }

        char comm[16];
        bpf_probe_read(&(comm), sizeof(comm), ctx->comm);
        int pid = ctx->pid;
        u64 ts = bpf_ktime_get_ns();
        u64 processor_id = bpf_get_smp_processor_id();

        //
        // // if (ret==0) {
        // //         u64 thread_cycles_sample = cycles_thread.perf_read(processor_id);
        // //         u64 core_cycles_sample = cycles_core.perf_read(processor_id);
        // //         u64 instruction_retired_thread = instr_thread.perf_read(processor_id);
        // //         update_cycles_count(ctx, pid, bpf_selector, step, processor_id, thread_cycles_sample, core_cycles_sample, instruction_retired_thread, ts);
        // // }
        //
        // //account data to the father
        // u64 tgid_pid = bpf_get_current_pid_tgid();
        // int tgid = tgid_pid >> 32;
        //
        // struct pid_status tg_status;
        // if(tgid == 0) {
        //         ret = bpf_probe_read(&tg_status, sizeof(tg_status), idles.lookup(&(processor_id)));
        // } else {
        //         ret = bpf_probe_read(&tg_status, sizeof(tg_status), pids.lookup(&(tgid)));
        // }
        //
        // if(ret == 0) {
        //
        //         //retrieve data about the exiting pid
        //         struct pid_status status_old;
        //         status_old.pid = -1;
        //
        //         /**
        //          * Fetch the status of the exiting pid.
        //          * If the pid is 0 then use the idles perf_hash
        //          */
        //         if(pid == 0) {
        //                 ret = bpf_probe_read(&status_old, sizeof(status_old), idles.lookup(&(processor_id)));
        //         } else {
        //                 ret = bpf_probe_read(&status_old, sizeof(status_old), pids.lookup(&(pid)));
        //         }
        //
        //         if(ret == 0) {
        //
        //                 // do the summation for all the sockets when the data
        //                 // for a given socket are updated
        //
        //                 #pragma clang loop unroll(full)
        //                 for(int array_index = 0; array_index<NUM_SLOTS; array_index++) {
        //                         if(array_index % SELECTOR_DIM == bpf_selector) {
        //                                 u64 last_ts_pid_in = status_old.ts[array_index];
        //                                 u64 last_ts_tgid_in = tg_status.ts[array_index];
        //
        //                                 if(last_ts_tgid_in + step > ts) {
        //                                         if(last_ts_pid_in + step > ts){
        //                                                 tg_status.ts[array_index] = ts;
        //                                                 tg_status.cycles[array_index] += status_old.cycles[array_index];
        //                                                 tg_status.weighted_cycles[array_index] += status_old.weighted_cycles[array_index];
        //                                                 tg_status.instruction_retired[array_index] += status_old.instruction_retired[array_index];
        //                                                 tg_status.time_ns[array_index] += status_old.time_ns[array_index];
        //                                                 tg_status.bpf_selector = bpf_selector;
        //                                         }
        //                                 } else {
        //                                         if(last_ts_pid_in + step > ts){
        //                                                 tg_status.ts[array_index] = ts;
        //                                                 tg_status.cycles[array_index] = status_old.cycles[array_index];
        //                                                 tg_status.weighted_cycles[array_index] = status_old.weighted_cycles[array_index];
        //                                                 tg_status.instruction_retired[array_index] = status_old.instruction_retired[array_index];
        //                                                 tg_status.time_ns[array_index] = status_old.time_ns[array_index];
        //                                                 tg_status.bpf_selector = bpf_selector;
        //                                         }
        //                                 }
        //                         }
        //                 }
        //
        //                 if(tgid == 0) {
        //                         idles.update(&processor_id, &tg_status);
        //                 } else {
        //                         pids.update(&tgid, &tg_status);
        //                 }
        //         }
        // }

        //send_error(ctx, tgid);
        //send_error(ctx, pid);

        //remove the pid from the table if there
        pids.delete(&pid);

        struct proc_topology topology_info;
        bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));

        topology_info.running_pid = 0;
        topology_info.ts = ts;
#ifdef PERFORMANCE_COUNTERS
        topology_info.cycles_thread = cycles_thread.perf_read(processor_id);
        topology_info.cycles_core = cycles_core.perf_read(processor_id);
        topology_info.instruction_thread = instr_thread.perf_read(processor_id);
        topology_info.cache_misses = cache_misses.perf_read(processor_id);
        topology_info.cache_refs = cache_refs.perf_read(processor_id);
        topology_info.cycles_core_delta_sibling = 0;
#endif

        processors.update(&processor_id, &topology_info);

        return 0;
}

int timed_trace(struct bpf_perf_event_data *perf_ctx) {

        // Keys for the conf hash
        int selector_key = BPF_SELECTOR_INDEX;
        int old_selector_key = BPF_SELECTOR_INDEX_OLD;
        int step_key = BPF_TIMESLICE;
        int switch_count_key = BPF_SWITCH_COUNT;

        // Slot iterator for the selector
        int array_index = 0;

        // Binary selector to avoid event overwriting
        unsigned int bpf_selector = 0;
        int ret = 0;
        ret = bpf_probe_read(&bpf_selector, sizeof(bpf_selector), conf.lookup(&selector_key));
        // If selector is not in place correctly, signal debug error and stop tracing routine
        if (ret!= 0 || bpf_selector > 1) {
                send_perf_error(perf_ctx, BPF_SELECTOR_NOT_IN_PLACE);
                return 0;
        }


        // Retrieve general switch count
        unsigned int switch_count = 0;
        ret = 0;
        ret = bpf_probe_read(&switch_count, sizeof(switch_count), conf.lookup(&switch_count_key));

        /**
         * Retrieve old selector to update switch count correctly
         */
        unsigned int old_bpf_selector = 0;
        ret = 0;
        ret = bpf_probe_read(&old_bpf_selector, sizeof(old_bpf_selector), conf.lookup(&old_selector_key));
        if (ret!= 0 || old_bpf_selector > 1) {
                send_perf_error(perf_ctx, OLD_BPF_SELECTOR_NOT_IN_PLACE);
                return 0;
        } else if(old_bpf_selector != bpf_selector) {
                switch_count = 1;
                conf.update(&switch_count_key, &switch_count);
                conf.update(&old_selector_key, &bpf_selector);
        }

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
                send_perf_error(perf_ctx, TIMESTEP_NOT_IN_PLACE);
                return 0;
        }

        int current_pid = bpf_get_current_pid_tgid();

        /* Read the values of the performance counters to update the data
         * inside our hashmap
         */
        u64 processor_id = bpf_get_smp_processor_id();
#ifdef PERFORMANCE_COUNTERS
        u64 thread_cycles_sample = cycles_thread.perf_read(processor_id);
        u64 core_cycles_sample = cycles_core.perf_read(processor_id);
        u64 instruction_retired_thread = instr_thread.perf_read(processor_id);
        u64 cache_misses_thread = cache_misses.perf_read(processor_id);
        u64 cache_refs_thread = cache_refs.perf_read(processor_id);
#endif
        u64 ts = bpf_ktime_get_ns();

        if (ret == 0) {
#ifdef PERFORMANCE_COUNTERS
                update_cycles_count(perf_ctx, current_pid, bpf_selector, step, processor_id, thread_cycles_sample, core_cycles_sample, instruction_retired_thread, cache_misses_thread, cache_refs_thread, ts);
#else
                update_cycles_count(perf_ctx, current_pid, bpf_selector, step, processor_id, ts);
#endif
        }


        // Fetch more data about processor we are currently dealing with
        ret = 0;
        struct proc_topology topology_info;
        ret = bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));
        if(ret!= 0 || topology_info.ht_id > NUM_CPUS) {
                send_perf_error(perf_ctx, CORRUPTED_TOPOLOGY_MAP);
                return 0;
        }

        //update topology info since we are forcing the update with a timer
        topology_info.running_pid = current_pid;
        topology_info.ts = ts;
#ifdef PERFORMANCE_COUNTERS
        topology_info.cycles_thread = thread_cycles_sample;
        topology_info.cycles_core_delta_sibling = 0;
        topology_info.cycles_core = core_cycles_sample;
        topology_info.instruction_thread = instruction_retired_thread;
        topology_info.cache_misses = cache_misses_thread;
        topology_info.cache_refs = cache_refs_thread;
#endif
        processors.update(&processor_id, &topology_info);

        global_timestamps.update(&bpf_selector, &ts);

        send_perf_error(perf_ctx, BPF_PROCEED_WITH_DEBUG_MODE);

        return 0;
}
