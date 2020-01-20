#!/usr/bin/env python2
import logging
import os.path
import snap_plugin.v1 as snap
import time
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from kubernetes import config, client, watch


LOG = logging.getLogger(__name__)


class ContainerNamer(snap.Collector):
    """ContainerNamer

    Streams assosiations between container names and ids
    """
    def __init__(self, name, description, **kwargs):
        super(ContainerNamer, self).__init__(name, description, **kwargs)
        #kube_conf = os.path.abspath("/home/snap/plugins/snap_plugin_collector_container_namer/kube_config")
        #config.load_kube_config(kube_conf)
        config.load_incluster_config()
        self.v1 = client.CoreV1Api()

        # Load config file with default values
        self.config = {}
        self.output_format = ""
        self.window_mode = ""
        self.customer_id = ""

        try:
            with open('/hyppo-config/config.yaml', 'r') as config_file:
                self.config = yaml.load(config_file)
        except Exception:
            try:
                with open('hyppo_monitor/config.yaml', 'r') as config_file:
                    self.config = yaml.load(config_file)
            except Exception:
                LOG.error("Couldn't find a config file, current path is %s", os.getcwd())

        try:
            self.output_format = self.config["output_format"]
            self.window_mode = self.config["window_mode"]
            self.customer_id = self.config["customer_id"]
        except KeyError as e:
            self.output_format = "console"
            self.window_mode = "fixed"
            self.customer_id = "not_registered"



    def get_config_policy(self):
        LOG.debug("GetConfigPolicy called on ContainerNamer")
        return snap.ConfigPolicy()

    def collect(self, metrics):
        LOG.debug("Names collection called on ContainerNamer")
        metrics_to_stream = []
        ts = time.time()

        for pod in self.v1.list_pod_for_all_namespaces(watch=False).items:
            try:
                for container in pod.spec.containers:
                    # Get the container id filtering container
                    # statuses with current container name
                    container_id = next((cstat.container_id
                        for cstat in pod.status.container_statuses
                        if cstat.name == container.name))
                    # Clean the id and take only 12 characters
                    if container_id is not None and "/" in container_id:
                        container_id = container_id.split("/")[-1][0:12]
                        metric = snap.Metric(
                            namespace=[
                                snap.NamespaceElement(value="hyppo"),
                                snap.NamespaceElement(value="hyppo-container-namer"),
                                snap.NamespaceElement(value="container-name"),
                                snap.NamespaceElement(value=self.customer_id),
                                snap.NamespaceElement(value=pod.metadata.namespace),
                                snap.NamespaceElement(value=pod.spec.node_name),
                                snap.NamespaceElement(value=pod.metadata.name),
                                snap.NamespaceElement(value=container.name),
                                snap.NamespaceElement(value="container_id")
                            ],
                            version=1,
                            tags={"mtype": "gauge"},
                            description="Name of the container",
                            data=container_id,
                            timestamp=ts
                        )
                        metrics_to_stream.append(metric)

            except Exception:
                Log.error("Error collecting container names")

            if pod.status.pod_ip != None:
                metric = snap.Metric(
                    namespace=[
                        snap.NamespaceElement(value="hyppo"),
                        snap.NamespaceElement(value="hyppo-container-namer"),
                        snap.NamespaceElement(value="pod-ip"),
                        snap.NamespaceElement(value=self.customer_id),
                        snap.NamespaceElement(value=pod.metadata.namespace),
                        snap.NamespaceElement(value=pod.spec.node_name),
                        snap.NamespaceElement(value=pod.metadata.name),
                        snap.NamespaceElement(value="ip")
                    ],
                    version=1,
                    tags={"mtype": "gauge"},
                    description="pod ip address",
                    data=pod.status.pod_ip,
                    timestamp=ts
                )
                metrics_to_stream.append(metric)
        # time.sleep(1)

        for service in self.v1.list_service_for_all_namespaces(watch=False).items:
            try:
                metric = snap.Metric(
                    namespace=[
                        snap.NamespaceElement(value="hyppo"),
                        snap.NamespaceElement(value="hyppo-container-namer"),
                        snap.NamespaceElement(value="service-ip"),
                        snap.NamespaceElement(value=self.customer_id),
                        snap.NamespaceElement(value=service.metadata.namespace),
                        snap.NamespaceElement(value=service.metadata.name),
                        snap.NamespaceElement(value="ip")
                    ],
                    version=1,
                    tags={"mtype": "gauge"},
                    description="service ip address",
                    data=service.spec.cluster_ip,
                    timestamp=ts
                )
                metrics_to_stream.append(metric)

                if service.spec.selector:
                    selector = ''
                    for k,v in service.spec.selector.items():
                        selector += k + '=' + v + ','
                    selector = selector[:-1]

                    for pod in self.v1.list_pod_for_all_namespaces(label_selector=selector).items:
                        metric = snap.Metric(
                            namespace=[
                                snap.NamespaceElement(value="hyppo"),
                                snap.NamespaceElement(value="hyppo-container-namer"),
                                snap.NamespaceElement(value="service-pod"),
                                snap.NamespaceElement(value=self.customer_id),
                                snap.NamespaceElement(value=service.metadata.namespace),
                                snap.NamespaceElement(value=pod.spec.node_name),
                                snap.NamespaceElement(value=service.metadata.name),
                                snap.NamespaceElement(value="pod")
                            ],
                            version=1,
                            tags={"mtype": "gauge"},
                            description="pod attached to service",
                            data=pod.metadata.name,
                            timestamp=ts
                        )
                        metrics_to_stream.append(metric)

            except Exception:
                LOG.debug("exception while reading k8s service data")

        # list nodes and ip addresses
        for node in self.v1.list_node(watch=False).items:
            for address in node.status.addresses:

                metric = snap.Metric(
                    namespace=[
                        snap.NamespaceElement(value="hyppo"),
                        snap.NamespaceElement(value="hyppo-container-namer"),
                        snap.NamespaceElement(value="node-ip"),
                        snap.NamespaceElement(value=self.customer_id),
                        snap.NamespaceElement(value=node.metadata.name),
                        snap.NamespaceElement(value="ip")
                    ],
                    version=1,
                    tags={"mtype": "gauge"},
                    description="pod ip address",
                    data=address.address,
                    timestamp=ts
                )
                metrics_to_stream.append(metric)


        return metrics_to_stream

    def update_catalog(self, config):
        LOG.debug("update_catalog called on ContainerNamer")

        metrics = []
        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-container-namer"),
                snap.NamespaceElement(value="container-name"),
                snap.NamespaceElement.dynamic_namespace_element(name="customer_id", description="Customer ID"),
                snap.NamespaceElement.dynamic_namespace_element(name="namespace", description="Kubernetes Namespace"),
                snap.NamespaceElement.dynamic_namespace_element(name="node_name", description="Kubernetes Node Name"),
                snap.NamespaceElement.dynamic_namespace_element(name="pod_name", description="Kubernetes Pod Name"),
                snap.NamespaceElement.dynamic_namespace_element(name="container_name", description="Container Name"),
                snap.NamespaceElement(value="container_id"),
                      ],
            version=1,
            tags={"mtype": "gauge"},
            description="Container ID",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-container-namer"),
                snap.NamespaceElement(value="pod-ip"),
                snap.NamespaceElement.dynamic_namespace_element(name="customer_id", description="Customer ID"),
                snap.NamespaceElement.dynamic_namespace_element(name="namespace", description="Kubernetes Namespace"),
                snap.NamespaceElement.dynamic_namespace_element(name="node_name", description="Kubernetes Node Name"),
                snap.NamespaceElement.dynamic_namespace_element(name="pod_name", description="Kubernetes Pod Name"),
                snap.NamespaceElement(value="ip"),
                      ],
            version=1,
            tags={"mtype": "gauge"},
            description="pod ip address",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-container-namer"),
                snap.NamespaceElement(value="service-ip"),
                snap.NamespaceElement.dynamic_namespace_element(name="customer_id", description="Customer ID"),
                snap.NamespaceElement.dynamic_namespace_element(name="namespace", description="Kubernetes Namespace"),
                snap.NamespaceElement.dynamic_namespace_element(name="service_name", description="Kubernetes Service Name"),
                snap.NamespaceElement(value="ip"),
                      ],
            version=1,
            tags={"mtype": "gauge"},
            description="service ip address",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-container-namer"),
                snap.NamespaceElement(value="service-pod"),
                snap.NamespaceElement.dynamic_namespace_element(name="customer_id", description="Customer ID"),
                snap.NamespaceElement.dynamic_namespace_element(name="namespace", description="Kubernetes Namespace"),
                snap.NamespaceElement.dynamic_namespace_element(name="node_name", description="Kubernetes Node Name"),
                snap.NamespaceElement.dynamic_namespace_element(name="service_name", description="Kubernetes Service Name"),
                snap.NamespaceElement(value="pod"),
                      ],
            version=1,
            tags={"mtype": "gauge"},
            description="pod attached to service",
        )
        metrics.append(metric)

        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-container-namer"),
                snap.NamespaceElement(value="node-ip"),
                snap.NamespaceElement.dynamic_namespace_element(name="customer_id", description="Customer ID"),
                snap.NamespaceElement.dynamic_namespace_element(name="node_name", description="Kubernetes Node Name"),
                snap.NamespaceElement(value="ip"),
                      ],
            version=1,
            tags={"mtype": "gauge"},
            description="node ip address",
        )
        metrics.append(metric)

        return metrics


if __name__ == "__main__":
    ContainerNamer("container-namer", 1).start_plugin()
