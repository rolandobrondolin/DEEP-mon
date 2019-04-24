from __future__ import absolute_import, division, print_function
import pprint
import json
# from collections import namedtuple
from collections import OrderedDict

from k8s_client import K8SClient

# PodInfoNew = namedtuple("PodInfoNew", ["cluster_name",
                                       # "namespace",
                                       # "host_ip",
                                       # "pod_ip",
                                       # "hostname",
                                       # "name",
                                       # "container_info"])

# ContainerInfo = namedtuple("ContainerInfo", ["id", "name", "image", "command"])


class PodHandler():

    def __init__(self):
        self.api_client = K8SClient()

    def get_all_pods(self):
        """Returns a list of pods with pod and cluster information
           for all pods running in the cluster"""
        pods = self.api_client.get_all_pods()
        pod_info = [self._create_pod_info(pod) for pod in pods.items]
        return pod_info

    def _create_pod_info(self, pod):
        return {"cluster_name": pod.metadata.cluster_name,
                "namespace": pod.metadata.namespace,
                "host_ip": pod.status.host_ip,
                "pod_ip": pod.status.pod_ip,
                "hostname": pod.spec.hostname,
                "name": pod.metadata.name,
                "container_info": self._extract_container_info(pod)}

    def _extract_container_info(self, pod):
        containers = pod.spec.containers
        container_statuses = pod.status.container_statuses
        container_info = [
            {"id": self._get_container_id(container, container_statuses),
             "name": container.name,
             "image": container.image,
             "command": container.command} for container in containers]

        return container_info

    def _get_container_id(self, container, container_statuses):
        for status in container_statuses:
            if status.name == container.name:
                return status.container_id
            return "Missing ID"


ph = PodHandler()
pods = ph.get_all_pods()
for pod in pods:
    pprint.pprint(pod, indent=4)
    print()
