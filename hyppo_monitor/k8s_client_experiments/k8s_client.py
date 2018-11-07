# Be ready for Python 3
from __future__ import (absolute_import,
                        division,
                        print_function,
                        unicode_literals)
from kubernetes import (client, config)
from pod_info import PodInfo, NullPodInfo
import threading


class K8SClient():

    def __init__(self, kube_conf=None):
        config.load_kube_config(kube_conf)
        self.v1 = client.CoreV1Api()
        self.memo = {}

    def get_all_pods(self):
        return self.v1.list_pod_for_all_namespaces(watch=False)

    def get_container_pod(self, container_info):
        return self._get_container_pod(container_info)

    def _get_container_pod(self, container_info):
        if container_info.container_id in self.memo:
            return self.memo[container_info.container_id]
        else:
            thread = threading.Thread(
                    target=self._run_threaded_query, args=(container_info,))
            thread.start()
            return NullPodInfo()

    def _run_threaded_query(self, container_info):
        pods = self.v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            for container_status in pod.status.container_statuses:
                if (container_info.container_id ==
                        container_status.container_id.split("/")[-1][0:12]):
                    self.memo[container_info.container_id] = PodInfo(pod)
