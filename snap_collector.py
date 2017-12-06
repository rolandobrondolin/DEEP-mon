#!/usr/bin/env python
import sys
sys.path.insert(0, "/home/rolando/dockercap_monitor")
from dockercap_monitor.monitor_main import MonitorMain
import snap_plugin.v1 as snap
import time
import logging

LOG = logging.getLogger(__name__)

class HyppoStreamCollector(snap.StreamCollector):

    def __init__(self, name, description, **kwargs):
        super(HyppoStreamCollector, self).__init__(name, description, **kwargs)
        self.hyppo_monitor = MonitorMain("")
        self.time_to_sleep = self.hyppo_monitor.sample_controller.get_sleep_time()

    def get_config_policy(self):
        LOG.debug("GetConfigPolicy called on HyppoStreamCollector")
        return snap.ConfigPolicy(
            [
                ("HyppoStreamCollector"),
                [
                    (
                        "kube_config_path",
                        snap.StringRule(default = "", required = False)
                    )
                ]
            ]
        )

    def stream(self, metrics):
        LOG.debug("Metrics collection called on HyppoStreamCollector")
        metrics_to_stream = []

        time.sleep(self.time_to_sleep)
        start_time = time.time()

        sample_array = self.hyppo_monitor.get_sample()
        sample = sample_array[0]
        container_list = sample_array[1]

        #add general metrics
        metrics_to_stream.extend(sample.to_snap(start_time))

        #here wrap up things to match snap format
        for key, value in container_list.iteritems():
            metrics_to_stream.extend(value.to_snap(start_time))
            metrics_to_stream.append(value.get_snap_container_id(start_time))
            metrics_to_stream.append(value.get_snap_cycles(start_time))
            metrics_to_stream.append(value.get_snap_instructions(start_time))
            metrics_to_stream.append(value.get_snap_power(start_time))
            metrics_to_stream.append(value.get_snap_cpu(start_time))

        self.time_to_sleep = self.hyppo_monitor.sample_controller.get_sleep_time() \
            - (time.time() - start_time)

        return metrics_to_stream

    def update_catalog(self, config):
        LOG.debug("update_catalog called on HyppoStreamCollector")
        metrics = []
        #general metrics
        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value="sample"),
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
                snap.NamespaceElement(value="sample"),
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
                snap.NamespaceElement(value="sample"),
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
                snap.NamespaceElement(value="sample"),
                snap.NamespaceElement(value="active_power"),
            ],
            version=1,
            tags={"mtype": "gauge"},
            description="Total active power",
        )
        metrics.append(metric)

        #pid related metrics
        for key in ("pid", "cycles", "instructions", "time_ns", "power", "cpu"):
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="hyppo-monitor"),
                    snap.NamespaceElement(value="thread"),
                    snap.NamespaceElement.dynamic_namespace_element(name="pid", description="pid of the process"),
                    snap.NamespaceElement(value=key)
                ],
                version=1,
                tags={"mtype": "gauge"},
                description=key,
            )
            metrics.append(metric)
        #container related metrics
        for key in ("ID", "cycles", "instructions", "time_ns", "power", "cpu"):
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="hyppo-monitor"),
                    snap.NamespaceElement(value="container"),
                    snap.NamespaceElement.dynamic_namespace_element(name="id", description="container id"),
                    snap.NamespaceElement(value=key)
                ],
                version=1,
                tags={"mtype": "gauge"},
                description=key,
            )
            metrics.append(metric)
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="hyppo-monitor"),
                    snap.NamespaceElement(value="container"),
                    snap.NamespaceElement(value=key),
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
