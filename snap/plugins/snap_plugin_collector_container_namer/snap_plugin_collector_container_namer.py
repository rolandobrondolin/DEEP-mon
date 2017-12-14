#!/usr/bin/env python2
import logging
import os.path
import snap_plugin.v1 as snap
import time

from kubernetes import config, client, watch


LOG = logging.getLogger(__name__)


class ContainerNamer(snap.StreamCollector):
    """ContainerNamer

    Streams assosiations between container names and ids
    """
    def __init__(self, name, description, **kwargs):
        super(ContainerNamer, self).__init__(name, description, **kwargs)
        kube_conf = os.path.expanduser("/home/snap/plugins/snap_plugin_collector_container_namer/kube_config")
        config.load_kube_config(kube_conf)
        self.v1 = client.CoreV1Api()
        self.user_id = "not_registered"

    def get_config_policy(self):
        LOG.debug("GetConfigPolicy called on ContainerNamer")
        return snap.ConfigPolicy(
            [
                ("/hyppo/container-namer"),
                [
                    (
                        "user_id",
                        snap.StringRule(default="not_registered", required=True)
                    )
                ]
            ]
        )

    def stream(self, metrics):
        LOG.debug("Names collection called on ContainerNamer")
        metrics_to_stream = []
        for i in range(0, 10):
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="hyppo-monitor"),
                    snap.NamespaceElement(value=self.user_id),
                    snap.NamespaceElement(value=str(i)),
                    snap.NamespaceElement(value=str(i)),
                    snap.NamespaceElement(value=str(i)),
                    snap.NamespaceElement(value="container_name")
                ],
                version=1,
                tags={"mtype": "gauge"},
                description="Random float",
                data=str(i),
                timestamp=time.time()
            )
            metrics_to_stream.append(metric)
        time.sleep(1)


        # for pod in self.v1.list_pod_for_all_namespaces(watch=False).items:
            # for container in pod.spec.containers:
                # # Get the container id filtering container
                # # statuses with current container name
                # container_id = next((cstat.container_id
                    # for cstat in pod.status.container_statuses
                    # if cstat.name == container.name))
                # # Clean the id and take only 12 characters
                # container_id = container_id.split("/")[-1][0:12]
                # metric = snap.Metric(
                    # namespace=[
                        # snap.NamespaceElement(value="hyppo"),
                        # snap.NamespaceElement(value="hyppo-monitor"),
                        # snap.NamespaceElement(value=self.user_id),
                        # snap.NamespaceElement(value=pod.metadata.namespace),
                        # snap.NamespaceElement(value=pod.metadata.name),
                        # snap.NamespaceElement(value=container_id),
                        # snap.NamespaceElement(value="container_name")
                    # ],
                    # version=1,
                    # tags={"mtype": "gauge"},
                    # description="Random float",
                    # data=container.name,
                    # timestamp=time.time()
                # )
                # metrics_to_stream.append(metric)
        # time.sleep(1)

        return metrics_to_stream

    def update_catalog(self, config):
        LOG.debug("update_catalog called on ContainerNamer")

        metrics = []
        metric = snap.Metric(
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement.dynamic_namespace_element(name="user_id", description="user id"),
                snap.NamespaceElement.dynamic_namespace_element(name="namespace", description="Kubernetes Namespace"),
                snap.NamespaceElement.dynamic_namespace_element(name="pod_name", description="Kubernetes Pod Name"),
                snap.NamespaceElement.dynamic_namespace_element(name="container_id", description="Container ID"),
                snap.NamespaceElement(value="container_name"),
                      ],
            version=1,
            tags={"mtype": "gauge"},
            description="Container Name",
        )
        metrics.append(metric)

        return metrics


if __name__ == "__main__":
    ContainerNamer("container-namer", 1).start_plugin()
