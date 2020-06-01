# /usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function, division
from bpf_collector import BpfCollector
from proc_topology import ProcTopology
from sample_controller import SampleController
from process_table import ProcTable
from net_collector import NetCollector
from mem_collector import MemCollector
from disk_collector import DiskCollector
from rapl import rapl
import os
import socket
import snap_plugin.v1 as snap
import time
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

class MonitorMain():

    def __init__(self, output_format, window_mode, debug_mode, net_monitor, nat_trace, print_net_details, dynamic_tcp_client_port_masking, power_measure, memory_measure, disk_measure, file_measure):
        self.output_format = output_format
        self.window_mode = window_mode
        # TODO: Don't hardcode the frequency
        self.frequency = 1

        self.topology = ProcTopology()
        self.collector = BpfCollector(self.topology, debug_mode, power_measure)
        self.sample_controller = SampleController(self.topology.get_hyperthread_count())
        self.process_table = ProcTable()
        self.rapl_monitor = rapl.RaplMonitor(self.topology)
        self.started = False

        self.print_net_details = print_net_details
        self.net_monitor = net_monitor
        self.dynamic_tcp_client_port_masking = dynamic_tcp_client_port_masking
        self.net_collector = None

        self.mem_measure = memory_measure
        self.mem_collector = None

        self.disk_measure = disk_measure
        self.file_measure = file_measure
        self.disk_collector = None

        if self.net_monitor:
            self.net_collector = NetCollector(trace_nat = nat_trace, dynamic_tcp_client_port_masking=dynamic_tcp_client_port_masking)
        
        if self.mem_measure:
            self.mem_collector = MemCollector()

        if self.disk_measure or self.file_measure:
            self.disk_collector = DiskCollector(disk_measure, file_measure)

    def get_window_mode(self):
        return self.window_mode

    def get_sample_controller(self):
        return self.sample_controller

    def _start_bpf_program(self, window_mode):
        if window_mode == 'dynamic':
            self.collector.start_capture(self.sample_controller.get_timeslice())
            if self.net_monitor:
                self.net_collector.start_capture()
            if (self.disk_measure or self.file_measure):
                self.disk_collector.start_capture()
        elif window_mode == 'fixed':
            self.collector.start_timed_capture(frequency=self.frequency)
            if self.net_monitor:
                self.net_collector.start_capture()
            if (self.disk_measure or self.file_measure):
                self.disk_collector.start_capture()
        else:
            print("Please provide a window mode")


    def get_sample(self):
        if not self.started:
            self._start_bpf_program(self.window_mode)
            self.started = True

        sample = self.collector.get_new_sample(self.sample_controller, self.rapl_monitor)
        # clear metrics for the new sample
        self.process_table.reset_metrics_and_evict_stale_processes(sample.get_max_ts())
        # add stuff to cumulative process table

        mem_dict = None
        disk_dict = None
        file_dict = {}

        if self.mem_collector:
            mem_dict = self.mem_collector.get_mem_dictionary()
        if self.disk_measure or self.file_measure:
            aggregate_disk_sample = self.disk_collector.get_sample()
            if self.disk_collector:
                disk_dict = aggregate_disk_sample['disk_sample']
            if self.file_measure:
                file_dict = aggregate_disk_sample['file_sample']

        nat_data = []
        if self.net_monitor:
            net_sample = self.net_collector.get_sample()
            self.process_table.add_process_from_sample(sample, \
                net_dictionary=net_sample.get_pid_dictionary(), \
                nat_dictionary=net_sample.get_nat_dictionary())
        else:
            self.process_table.add_process_from_sample(sample)

        # Now, extract containers!
        container_list = self.process_table.get_container_dictionary(mem_dict, disk_dict)

        return [sample, container_list, self.process_table.get_proc_table(), nat_data, file_dict]


    def monitor_loop(self):
        if self.window_mode == 'dynamic':
            time_to_sleep = self.sample_controller.get_sleep_time()
        else:
            time_to_sleep = 1 / self.frequency

        while True:

            if time_to_sleep > 0:
                time.sleep(time_to_sleep)
            start_time = time.time()

            sample_array = self.get_sample()
            sample = sample_array[0]
            container_list = sample_array[1]

            if self.output_format == "json":
                for key, value in container_list.iteritems():
                    print(value.to_json())
                print(sample.get_log_json())

            elif self.output_format == "console":
                if self.print_net_details:
                    nat_data = sample_array[3]
                    for nat_rule in nat_data:
                        print(nat_rule)

                for key, value in sorted(container_list.items()):
                    print(value)

                    if self.print_net_details:
                        for item in value.get_network_transactions():
                            print(item)
                        for item in value.get_nat_rules():
                            print(item)

                print('│')
                print('└─╼', end='\t')
                print(sample.get_log_line())
                print()
                print()

            if self.window_mode == 'dynamic':
                time_to_sleep = self.sample_controller.get_sleep_time() \
                    - (time.time() - start_time)
            else:
                time_to_sleep = 1 / self.frequency - (time.time() - start_time)

    def snap_monitor_loop(self):
        if self.window_mode == 'dynamic':
            time_to_sleep = self.sample_controller.get_sleep_time()
        else:
            time_to_sleep = 1 / self.frequency

        user_id = "not_registered"
        while True:
            metrics_to_stream = []

            if time_to_sleep > 0:
                time.sleep(time_to_sleep)
            start_time = time.time()

            sample_array = self.get_sample()
            sample = sample_array[0]
            container_list = sample_array[1]
            proc_dict = sample_array[2]

            hostname = socket.gethostname()

            #add general metrics
            metrics_to_stream.extend(sample.to_snap(start_time, user_id, hostname))

            #here wrap up things to match snap format
            for key, value in container_list.iteritems():
                metrics_to_stream.extend(value.to_snap(start_time, user_id, hostname))

            #add threads from proc_table
            #for key, value in proc_dict.iteritems():
            #    metrics_to_stream.extend(value.to_snap(start_time, user_id, hostname))

            # put timestamp
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="hyppo-monitor"),
                    snap.NamespaceElement(value=user_id),
                    snap.NamespaceElement(value=hostname),
                    snap.NamespaceElement(value="ts"),
                ],
                version=1,
                description="timestamp",
                data=int(start_time),
                timestamp=start_time
            )
            metrics_to_stream.append(metric)

            if self.window_mode == 'dynamic':
                time_to_sleep = self.sample_controller.get_sleep_time() \
                    - (time.time() - start_time)
            else:
                time_to_sleep = 1 / self.frequency

            # print(str(time_to_sleep) + "," + str(self.sample_controller.get_sleep_time()) + "," + str(sample.get_sched_switch_count()))
if __name__ == "__main__":
    monitor = MonitorMain("console", "fixed", False, True, False, False, True, True, False, False, False)
    monitor.monitor_loop()
