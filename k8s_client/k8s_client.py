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
import threading


class K8SClient():

    def __init__(self):
        config.load_kube_config()
        self.v1 = client.CoreV1Api()
        self.memo = {}

    def get_container_name(self, container_info):
        name, pod = self._get_container_name_and_pod(container_info)
        return name

    def get_container_pod(self, container_info):
        name, pod = self._get_container_name_and_pod(container_info)
        return pod

    def _get_container_name_and_pod(self, container_info):
        if container_info.container_id in self.memo:
            return self.memo[container_info.container_id]
        else:
            thread = threading.Thread(
                    target=self._run_threaded_query, args=(container_info,))
            thread.start()
            return ("", None)

    def _run_threaded_query(self, container_info):
        pods = self.v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            for container_status in pod.status.container_statuses:
                if (container_info.container_id ==
                        container_status.container_id.split("/")[-1][0:12]):
                    ret = (container_status.name, pod)
                    self.memo[container_info.container_id] = ret
                    return ret
