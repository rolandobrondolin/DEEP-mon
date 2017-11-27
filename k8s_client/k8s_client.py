# Be ready for Python 3
from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals
)

from kubernetes import (
    client,
    config
)


class K8SClient():

    def __init__(self):
        # Configs can be set in Configuration class directly
        # or using helper utility
        config.load_kube_config()
        self.v1 = client.CoreV1Api()

    def get_container_name(self, container_info):
        name, pod = self._get_container_name_and_pod(container_info)
        return name

    def get_container_pod(self, container_info):
        name, pod = self._get_container_name_and_pod(container_info)
        return pod

    def _get_container_name_and_pod(self, container_info):
        pods = self.v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            for container_status in pod.status.container_statuses:
                # print("Status: ", container_status.container_id.split("/")[-1][0:12])
                # print("Info: ", container_info.container_id)
                if (container_info.container_id ==
                        container_status.container_id.split("/")[-1][0:12]):
                    return (container_status.name, pod)
