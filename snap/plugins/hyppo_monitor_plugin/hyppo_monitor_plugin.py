#!/usr/bin/env python

import os

import sys
from hyppo_monitor.monitor_main import MonitorMain
import snap_plugin.v1 as snap
import time
import logging
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

LOG = logging.getLogger(__name__)

class HyppoStreamCollector(snap.StreamCollector):

    def __init__(self, name, description, **kwargs):
        super(HyppoStreamCollector, self).__init__(name, description, **kwargs)

        # Load config file with default values
        self.config = {}
        self.output_format = ""
        self.window_mode = ""
        self.customer_id = ""
        self.debug_mode = False
        self.send_thread_data = False
        self.hostname = ""
        self.net_monitor = True
        self.nat_trace = True
        self.print_net_details = False
        self.dynamic_tcp_client_port_masking = False
        self.power_measure = False

        try:
            with open('/hyppo-config/config.yaml', 'r') as config_file:
                self.config = yaml.load(config_file)
        except Exception:
            try:
                with open('hyppo_monitor/config.yaml', 'r') as config_file:
                    self.config = yaml.load(config_file)
            except Exception:
                LOG.error("Couldn't find a config file, current path is %s", os.getcwd())

        #open hostname file
        hostFile = open("/etc/hosthostname","r")
        self.hostname = hostFile.read().rstrip().lower()
        hostFile.close()

        try:
            self.output_format = self.config["output_format"]
            self.window_mode = self.config["window_mode"]
            self.customer_id = self.config["customer_id"]
            self.debug_mode = self.config["debug_mode"]
            self.send_thread_data = self.config["send_thread_data"]
            self.net_monitor = self.config["net_monitor"]
            self.nat_trace = self.config["nat_trace"]
            self.print_net_details = False
            self.dynamic_tcp_client_port_masking = self.config["dynamic_tcp_client_port_masking"]
            self.power_measure = self.config["power_measure"]
        except KeyError as e:
            self.output_format = "console"
            self.window_mode = "fixed"
            self.customer_id = "not_registered"
            self.debug_mode = False
            self.send_thread_data = False
            self.net_monitor = True
            self.nat_trace = True
            self.print_net_details = False
            self.dynamic_tcp_client_port_masking = False
            self.power_measure = False

        self.hyppo_monitor = MonitorMain(self.output_format, self.window_mode, self.debug_mode, self.net_monitor, self.nat_trace, self.print_net_details, self.dynamic_tcp_client_port_masking, self.power_measure)

        if self.window_mode == "dynamic":
            self.time_to_sleep = self.hyppo_monitor.sample_controller.get_sleep_time()
        else:
            self.time_to_sleep = 1


    def get_config_policy(self):
        LOG.debug("GetConfigPolicy called on HyppoStreamCollector")
        return snap.ConfigPolicy()

    def stream(self, metrics):
        LOG.debug("Metrics collection called on HyppoStreamCollector")
        metrics_to_stream = []

        if self.time_to_sleep > 0:
            time.sleep(self.time_to_sleep)
        start_time = time.time()

        try:
            sample_array = self.hyppo_monitor.get_sample()
            sample = sample_array[0]
            container_list = sample_array[1]

            #add general metrics
            metrics_to_stream.extend(sample.to_snap(start_time, self.customer_id, self.hostname))

            #here wrap up things to match snap format
            for key, value in container_list.iteritems():
                metrics_to_stream.extend(value.to_snap(start_time, self.customer_id, self.hostname, self.net_monitor))

            #add threads from proc_table
            if self.send_thread_data == True:
                proc_dict = sample_array[2]
                for key, value in proc_dict.iteritems():
                    metrics_to_stream.extend(value.to_snap(start_time, self.customer_id, self.hostname))

            # put timestamp
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="hyppo-monitor"),
                    snap.NamespaceElement(value=self.customer_id),
                    snap.NamespaceElement(value=self.hostname),
                    snap.NamespaceElement(value="ts"),
                ],
                version=1,
                description="timestamp",
                data=int(start_time),
                timestamp=start_time
            )
            metrics_to_stream.append(metric)

        except Exception:
            LOG.error("exception while collecting data")

        if self.config["window_mode"] == "dynamic":
            self.time_to_sleep = self.hyppo_monitor.sample_controller.get_sleep_time() \
                - (time.time() - start_time)
        else:
            self.time_to_sleep = 1 - (time.time() - start_time)

        return metrics_to_stream



    def update_catalog(self, config):
        LOG.debug("update_catalog called on HyppoStreamCollector")

        #self.customer_id = config["customer_id"]

        metrics = []
        #general metrics
        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                snap.NamespaceElement(value="ts"),
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="timestamp",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                snap.NamespaceElement(value="host"),
                snap.NamespaceElement(value="summary"),
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="Host summary",
        )
        metrics.append(metric)

        #pid related metrics
        # skipping pid: for key in ("pid", "cycles", "instructions", "time_ns", "power", "cpu"):
        #for key in ("perf_summary"):
        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                snap.NamespaceElement(value="thread"),
                snap.NamespaceElement.dynamic_namespace_element(name="container_id", description="container id"),
                snap.NamespaceElement.dynamic_namespace_element(name="pid", description="pid of the process"),
                snap.NamespaceElement(value="perf_summary")
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="perf_summary",
        )
        metrics.append(metric)
        #container related metrics
        #skipping container id: for key in ("ID", "cycles", "instructions", "time_ns", "power", "cpu"):
        for key in ("perf_summary", "net_summary", "net_detail"):
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="hyppo-monitor"),
                    snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                    snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                    snap.NamespaceElement(value="container"),
                    snap.NamespaceElement.dynamic_namespace_element(name="id", description="container id"),
                    snap.NamespaceElement(value=key)
                ],
                version=1,
                tags={"mtype": "gauge"},
                description=key,
            )
            metrics.append(metric)

        return metrics

if __name__ == "__main__":
    HyppoStreamCollector("hyppo-monitor", 1).start_plugin()
