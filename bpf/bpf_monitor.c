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

#define STEP 1000000000 //2000000000
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
        int conf_key = 0;
        unsigned int bpf_selector = 0;
        bpf_probe_read(&bpf_selector, sizeof(bpf_selector), conf.lookup(&conf_key));
        // if selector is not in place correctly, signal debug error and stop
        // tracing routine
        if (bpf_selector > 1) {
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
        bpf_probe_read(&topology_info, sizeof(topology_info), processors.lookup(&processor_id));

        if(topology_info.ht_id > NUM_CPUS) {
                send_error(ctx, 2);
                return 0;
        }

        // fetch the status of the exiting pid
        struct pid_status status_old;
        status_old.pid = -1;
        // if the pid is 0, then use the idles perf_hash
        if(old_pid == 0) {
                bpf_probe_read(&status_old, sizeof(status_old), idles.lookup(&(processor_id)));
        } else {
                bpf_probe_read(&status_old, sizeof(status_old), pids.lookup(&(old_pid)));
        }

        //
        // Do things with the process exiting from execution
        //
        if(status_old.pid == old_pid) {
                //find the entry related to processor_id and its sibling
                u64 sibling_id = 0;
                bpf_probe_read(&sibling_id, sizeof(sibling_id), &topology_info.sibling_id);
                struct proc_topology *sibling_info = processors.lookup(&(sibling_id));
                if(!sibling_info) {
                        // wrong info on topology, do nothing
                        send_error(ctx, 3);
                        return 0;
                }
                u64 old_cycles = cycles;
                u64 old_time = ts;
                if(sibling_info->ts > topology_info.ts) {
                        old_time = sibling_info->ts;
                        old_cycles = sibling_info->cycles;
                } else if (topology_info.ts > 0) {
                        old_time = topology_info.ts;
                        old_cycles = topology_info.cycles;
                }

                u64 weight_factor = STD_FACTOR;
                u64 weight_enabler = 0;
                //find the sibling pid status
                int sibling_pid = 0;
                bpf_probe_read(&sibling_pid, sizeof(sibling_pid), &sibling_info->running_pid);
                struct pid_status sibling_process;
                if(sibling_pid == 0) {
                        //read from idles table
                        bpf_probe_read(&sibling_process, sizeof(sibling_process), idles.lookup(&(sibling_id)));
                } else {
                        //read from pids table
                        bpf_probe_read(&sibling_process, sizeof(sibling_process), pids.lookup(&(sibling_pid)));
                }

                if(sibling_process.pid == sibling_pid) {

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

                        if(sibling_process.bpf_selector != bpf_selector || last_ts_pid_in + STEP < ts) {
                                sibling_process.bpf_selector = bpf_selector;
                                if(bpf_selector) {
                                        sibling_process.weighted_cycles[1] = 0;
                                        sibling_process.time_ns[1] = 0;
                                        // ts of pid is updated on exit only
                                } else if (!bpf_selector) {
                                        sibling_process.weighted_cycles[0] = 0;
                                        sibling_process.time_ns[0] = 0;
                                        // ts of pid is updated on exit only
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
                } else {
                        // outdated info on pid table, do nothing
                        send_error(ctx, 5);
                        return 0;
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

                if(status_old.bpf_selector != bpf_selector || last_ts_pid_in + STEP < ts) {
                        status_old.bpf_selector = bpf_selector;
                        if(bpf_selector) {
                                status_old.weighted_cycles[1] = 0;
                                status_old.time_ns[1] = 0;
                                // ts of pid is updated on exit only
                        } else if (!bpf_selector) {
                                status_old.weighted_cycles[0] = 0;
                                status_old.time_ns[0] = 0;
                                // ts of pid is updated on exit only
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
        //no info on old status, let another enter sched build it

        //
        // handle new scheduled process
        //
        int new_pid = ctx->next_pid;
        struct pid_status status_new;
        if(new_pid == 0) {
                bpf_probe_read(&status_new, sizeof(status_new), idles.lookup(&(processor_id)));
        } else {
                bpf_probe_read(&status_new, sizeof(status_new), pids.lookup(&(new_pid)));
        }
        //If no status for PID, then create one, otherwise update selector
        if(status_new.pid != new_pid) {
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
