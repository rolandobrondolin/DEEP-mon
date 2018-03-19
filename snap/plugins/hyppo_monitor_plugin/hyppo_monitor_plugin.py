#!/usr/bin/env python
import sys
from hyppo_monitor.monitor_main import MonitorMain
import snap_plugin.v1 as snap
import time
import logging

LOG = logging.getLogger(__name__)

class HyppoStreamCollector(snap.StreamCollector):

    def __init__(self, name, description, **kwargs):
        super(HyppoStreamCollector, self).__init__(name, description, **kwargs)
        self.hyppo_monitor = MonitorMain("")
        self.time_to_sleep = self.hyppo_monitor.sample_controller.get_sleep_time()
        self.user_id = "not_registered"

    def get_config_policy(self):
        LOG.debug("GetConfigPolicy called on HyppoStreamCollector")
        return snap.ConfigPolicy(
            [
                ("/hyppo/hyppo-monitor"),
                [
                    (
                        "kube_config_path",
                        snap.StringRule(default = "", required = False)
                    ),
                    (
                        "user_id",
                        snap.StringRule(default = "not_registered", required = True)
                    )
                ]
            ]
        )

    def stream(self, metrics):
        LOG.debug("Metrics collection called on HyppoStreamCollector")
        metrics_to_stream = []

        if self.time_to_sleep > 0:
            time.sleep(self.time_to_sleep)
        start_time = time.time()

        sample_array = self.hyppo_monitor.get_sample()
        sample = sample_array[0]
        container_list = sample_array[1]
        proc_dict = sample_array[2]

        #open hostname file
        hostFile = open("/etc/hosthostname","r")
        hostname = hostFile.read().rstrip()
        hostFile.close()

        #add general metrics
        metrics_to_stream.extend(sample.to_snap(start_time, self.user_id, hostname))

        #here wrap up things to match snap format
        for key, value in container_list.iteritems():
            metrics_to_stream.extend(value.to_snap(start_time, self.user_id, hostname))

        #add threads from proc_table
        #for key, value in proc_dict.iteritems():
        #    metrics_to_stream.extend(value.to_snap(start_time, self.user_id, hostname))

        # put timestamp
        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value=self.user_id),
                snap.NamespaceElement(value=hostname),
                snap.NamespaceElement(value="ts"),
            ],
            version=1,
            description="timestamp",
            data=int(start_time),
            timestamp=start_time
        )
        metrics_to_stream.append(metric)

        self.time_to_sleep = self.hyppo_monitor.sample_controller.get_sleep_time() \
            - (time.time() - start_time)

        return metrics_to_stream

    def update_catalog(self, config):
        LOG.debug("update_catalog called on HyppoStreamCollector")

        #self.user_id = config["user_id"]

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
                snap.NamespaceElement(value="execution_time"),
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="Total execution time",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                snap.NamespaceElement(value="host"),
                snap.NamespaceElement(value="switch_count"),
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="Sched switch count",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                snap.NamespaceElement(value="host"),
                snap.NamespaceElement(value="timeslice"),
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="Timeslice",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                snap.NamespaceElement(value="host"),
                snap.NamespaceElement(value="package_power"),
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="Package power",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                snap.NamespaceElement(value="host"),
                snap.NamespaceElement(value="core_power"),
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="Core power",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                snap.NamespaceElement(value="host"),
                snap.NamespaceElement(value="dram_power"),
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="DRAM power",
        )
        metrics.append(metric)

        #pid related metrics
        # skipping pid: for key in ("pid", "cycles", "instructions", "time_ns", "power", "cpu"):
        for key in ("cycles", "instructions", "time_ns", "power", "cpu"):
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="hyppo-monitor"),
                    snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                    snap.NamespaceElement.dynamic_namespace_element(name="host_id", description="host id"),
                    snap.NamespaceElement(value="thread"),
                    snap.NamespaceElement.dynamic_namespace_element(name="container_id", description="container id"),
                    snap.NamespaceElement.dynamic_namespace_element(name="pid", description="pid of the process"),
                    snap.NamespaceElement(value=key)
                ],
                version=1,
                tags={"mtype": "gauge"},
                description=key,
            )
            metrics.append(metric)
        #container related metrics
        #skipping container id: for key in ("ID", "cycles", "instructions", "time_ns", "power", "cpu"):
        for key in ("cycles", "instructions", "time_ns", "power", "cpu"):
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
