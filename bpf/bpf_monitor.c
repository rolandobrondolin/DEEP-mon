struct pid_status {
        int pid;
        char comm[16];
        u64 weighted_cycles[2];
        u64 time_ns[2];
        // set which item of weighted_cycles should be used in bpf
        // in user space, the weighted_cycles is read and initialized
        unsigned int bpf_selector;
        u64 ts[2];
};
struct proc_topology {
        u64 ht_id;
        u64 sibling_id;
        u64 core_id;
        u64 processor_id;
        u64 cycles;
        u64 ts;
        int running_pid;
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

//#define DEBUG

#ifdef DEBUG
struct error_code {
        int err;
};

BPF_PERF_OUTPUT(err);
#endif

BPF_PERF_ARRAY(cpu_cycles, NUM_CPUS);
BPF_HASH(processors, u64, struct proc_topology);
BPF_HASH(pids, int, struct pid_status);
BPF_HASH(idles, u64, struct pid_status);
BPF_HASH(conf, int, unsigned int);

// Beware: Changing the step in userspace means invalidate the last sample
#define STEP_MIN 1000000000 //2000000000
#define STEP_MAX 4000000000 //2000000000

#define HAPPY_FACTOR 5
#define STD_FACTOR 1


static void send_error(struct sched_switch_args *ctx, int err_code) {
#ifdef DEBUG
        struct error_code error;
        error.err = err_code;
        err.perf_submit(ctx, &error, sizeof(error));
#endif
}

int trace_switch(struct sched_switch_args *ctx) {

        int selector_key = 0;
        int old_selector_key = 1;
        int step_key = 2;
        int switch_count_key = 3;

        unsigned int bpf_selector = 0;
        int ret = 0;
        ret = bpf_probe_read(&bpf_selector, sizeof(bpf_selector), conf.lookup(&selector_key));
        // if selector is not in place correctly, signal debug error and stop tracing routine
        if (ret!= 0 || bpf_selector > 1) {
                send_error(ctx, 1);
                return 0;
        }

        // retrieve general switch count
        unsigned int switch_count = 0;
        ret = 0;
        ret = bpf_probe_read(&switch_count, sizeof(switch_count), conf.lookup(&switch_count_key));

        //retrieve old selector to update switch count correctly
        unsigned int old_bpf_selector = 0;
        ret = 0;
        ret = bpf_probe_read(&old_bpf_selector, sizeof(old_bpf_selector), conf.lookup(&old_selector_key));
        if (ret!= 0 || old_bpf_selector > 1) {
                send_error(ctx, 1);
                return 0;
        } else if(old_bpf_selector != bpf_selector) {
          switch_count = 1;
          conf.update(&old_selector_key, &bpf_selector);
        } else {
          switch_count++;
        }
        conf.update(&switch_count_key, &switch_count);

        // retrieve sampling step
        // Beware: Increasing the step in userspace means that the next sample is invalid
        // Reducing the step in userspace is not an issue, give that it excludes data
        // that is inside an can be discarded
        unsigned int step = 1000000000;
        ret = bpf_probe_read(&step, sizeof(step), conf.lookup(&step_key));
        if (ret!= 0 || step < STEP_MIN || step > STEP_MAX) {
                send_error(ctx, 1);
                return 0;
        }


        // get data about processor and performance counters
        // lookup also the pid of the exiting process
        u64 processor_id = bpf_get_smp_processor_id();
        u64 cycles = cpu_cycles.perf_read(processor_id);
        u64 ts = bpf_ktime_get_ns();
        int old_pid = ctx->prev_pid;

        // fetch data about processor executing the thing
        struct proc_topology topology_info;
        ret = bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));
        if(ret!= 0 || topology_info.ht_id > NUM_CPUS) {
                send_error(ctx, 2);
                return 0;
        }

        // fetch the status of the exiting pid
        struct pid_status status_old;
        status_old.pid = -1;

        // if the pid is 0, then use the idles perf_hash
        if(old_pid == 0) {
                ret = bpf_probe_read(&status_old, sizeof(status_old), idles.lookup(&(processor_id)));
        } else {
                ret = bpf_probe_read(&status_old, sizeof(status_old), pids.lookup(&(old_pid)));
        }

        if(ret == 0) {
                u64 sibling_id = topology_info.sibling_id;
                struct proc_topology sibling_info;
                ret = bpf_probe_read(&sibling_info, sizeof(sibling_info), processors.lookup(&(sibling_id)));

                if(ret != 0) {
                        // wrong info on topology, do nothing
                        send_error(ctx, 3);
                        return 0;
                }
                u64 old_cycles = cycles;
                u64 old_time = ts;
                if (topology_info.ts > 0) {
                        old_time = topology_info.ts;
                        old_cycles = topology_info.cycles;
                }

                u64 weight_factor = STD_FACTOR;
                u64 weight_enabler = 0;
                //find the sibling pid status
                int sibling_pid = sibling_info.running_pid;
                struct pid_status sibling_process;
                if(sibling_pid == 0) {
                        //read from idles table
                        ret = bpf_probe_read(&sibling_process, sizeof(sibling_process), idles.lookup(&(sibling_id)));
                } else {
                        //read from pids table
                        ret = bpf_probe_read(&sibling_process, sizeof(sibling_process), pids.lookup(&(sibling_pid)));
                }

                if(ret == 0) {
                        // here just update the selector and reset counter if needed
                        u64 last_ts_pid_in = 0;
                        if(sibling_process.bpf_selector) {
                                last_ts_pid_in = sibling_process.ts[1];
                        } else if(!sibling_process.bpf_selector) {
                                last_ts_pid_in = sibling_process.ts[0];
                        } else {
                                send_error(ctx, 7);
                                return 0;
                        }

                        if(sibling_process.bpf_selector != bpf_selector || last_ts_pid_in + step < ts) {
                                sibling_process.bpf_selector = bpf_selector;
                                if(bpf_selector) {
                                        sibling_process.weighted_cycles[1] = 0;
                                        sibling_process.time_ns[1] = 0;
                                } else if (!bpf_selector) {
                                        sibling_process.weighted_cycles[0] = 0;
                                        sibling_process.time_ns[0] = 0;
                                } else {
                                        // selector corrupted, do nothing
                                        send_error(ctx, 8);
                                        return 0;
                                }
                        }

                        if(sibling_pid > 0) {
                                weight_factor = HAPPY_FACTOR;
                                weight_enabler = 1;
                        }
                        if(sibling_process.bpf_selector == 0) {
                                //discard sample if cycles counter did overflow
                                if (cycles > old_cycles) {
                                        sibling_process.weighted_cycles[0] += (cycles - old_cycles) + ((cycles - old_cycles)/weight_factor)*weight_enabler;
                                } else {
                                        send_error(ctx, old_pid);
                                }
                                sibling_process.time_ns[0] += ts - old_time;
                                sibling_process.ts[0] = ts;
                                if(sibling_pid == 0) {
                                        idles.update(&(sibling_id), &sibling_process);
                                } else {
                                        pids.update(&(sibling_pid), &sibling_process);
                                }
                        } else if (sibling_process.bpf_selector == 1) {
                                //discard sample if cycles counter did overflow
                                if (cycles > old_cycles) {
                                        sibling_process.weighted_cycles[1] += (cycles - old_cycles) + ((cycles - old_cycles)/weight_factor)*weight_enabler;
                                } else {
                                        send_error(ctx, old_pid);
                                }
                                sibling_process.time_ns[1] += ts - old_time;
                                sibling_process.ts[1] = ts;
                                if(sibling_pid == 0) {
                                        idles.update(&(sibling_id), &sibling_process);
                                } else {
                                        pids.update(&(sibling_pid), &sibling_process);
                                }
                        } else {
                                //selector corrupted, do nothing
                                send_error(ctx, 4);
                                return 0;
                        }

                        //update sibling process info
                        sibling_info.cycles = cycles;
                        sibling_info.ts = ts;
                        processors.update(&sibling_id, &sibling_info);
                }

                // here just update the selector and reset counter if needed
                u64 last_ts_pid_in = 0;
                if(status_old.bpf_selector) {
                        last_ts_pid_in = status_old.ts[1];
                } else if(!status_old.bpf_selector) {
                        last_ts_pid_in = status_old.ts[0];
                } else {
                        send_error(ctx, 7);
                        return 0;
                }

                if(status_old.bpf_selector != bpf_selector || last_ts_pid_in + step < ts) {
                        status_old.bpf_selector = bpf_selector;
                        if(bpf_selector) {
                                status_old.weighted_cycles[1] = 0;
                                status_old.time_ns[1] = 0;
                        } else if (!bpf_selector) {
                                status_old.weighted_cycles[0] = 0;
                                status_old.time_ns[0] = 0;
                        } else {
                                // selector corrupted, do nothing
                                send_error(ctx, 8);
                                return 0;
                        }
                }

                //increment counters on our pid
                if(status_old.bpf_selector == 0) {
                        //discard sample if cycles counter did overflow
                        if (cycles > old_cycles) {
                                status_old.weighted_cycles[0] += (cycles - old_cycles) + ((cycles - old_cycles)/weight_factor)*weight_enabler;
                        } else {
                                send_error(ctx, old_pid);
                        }
                        status_old.time_ns[0] += ts - old_time;
                        status_old.ts[0] = ts;
                        if(old_pid == 0) {
                                idles.update(&processor_id, &status_old);
                        } else {
                                pids.update(&old_pid, &status_old);
                        }
                } else if (status_old.bpf_selector == 1) {
                        //discard sample if cycles counter did overflow
                        if (cycles > old_cycles) {
                                status_old.weighted_cycles[1] += (cycles - old_cycles) + ((cycles - old_cycles)/weight_factor)*weight_enabler;
                        } else {
                                send_error(ctx, old_pid);
                        }
                        status_old.time_ns[1] += ts - old_time;
                        status_old.ts[1] = ts;
                        if(old_pid == 0) {
                                idles.update(&processor_id, &status_old);
                        } else {
                                pids.update(&old_pid, &status_old);
                        }
                } else {
                        // selector corrupted, do nothing
                        send_error(ctx, 6);
                        return 0;
                }
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
                send_error(ctx, -1 * new_pid);
                bpf_probe_read(&(status_new.comm), sizeof(status_new.comm), ctx->next_comm);
                status_new.pid = new_pid;
                status_new.ts[0] = ts;
                status_new.ts[1] = ts;
                status_new.weighted_cycles[0] = 0;
                status_new.weighted_cycles[1] = 0;
                status_new.time_ns[0] = 0;
                status_new.time_ns[1] = 0;
                status_new.bpf_selector = bpf_selector;
                if(new_pid == 0) {
                        idles.insert(&processor_id, &status_new);
                } else {
                        pids.insert(&new_pid, &status_new);
                }
        }
        //add info on new running pid into processors table
        topology_info.running_pid = new_pid;
        topology_info.cycles = cycles;
        topology_info.ts = ts;
        processors.update(&processor_id, &topology_info);
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
        topology_info.cycles = cpu_cycles.perf_read(processor_id);
        topology_info.ts = ts;

        processors.update(&processor_id, &topology_info);

        return 0;
}
