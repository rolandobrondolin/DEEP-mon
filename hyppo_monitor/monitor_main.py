# /usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function, division
from bpf_collector import BpfCollector
from proc_topology import ProcTopology
from sample_controller import SampleController
from process_table import ProcTable
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

    def __init__(self, output_format, window_mode):
        self.output_format = output_format
        self.window_mode = window_mode
        # TODO: Don't hardcode the frequency
        self.frequency = 1

        self.topology = ProcTopology()
        self.collector = BpfCollector(self.topology, False)
        self.sample_controller = SampleController(self.topology.get_hyperthread_count())
        self.process_table = ProcTable()
        self.rapl_monitor = rapl.RaplMonitor(self.topology)

        self._start_bpf_program(window_mode)


    def _start_bpf_program(self, window_mode):
        if window_mode == 'dynamic':
            self.collector.start_capture(self.sample_controller.get_timeslice())
        elif window_mode == 'fixed':
            self.collector.start_timed_capture(frequency=self.frequency)
        else:
            print("Please provide a window mode")


    def get_sample(self):
        sample = self.collector.get_new_sample(self.sample_controller, self.rapl_monitor)
        # add stuff to cumulative process table
        self.process_table.add_process_from_sample(sample)

        # Now, extract containers!
        container_list = self.process_table.get_container_dictionary()

        return [sample, container_list, self.process_table.get_proc_table()]


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
                print
                print(sample.get_log_json())
            elif self.output_format == "console":
                for key, value in sorted(container_list.items()):
                    print(value)
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
