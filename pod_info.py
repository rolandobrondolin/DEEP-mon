class PodInfo:

    def __init__(self, pod):
        self.cluster_name = pod.metadata.cluster_name
        self.namespace = pod.metadata.namespace
        self.host_ip = pod.status.host_ip
        self.pod_ip = pod.status.pod_ip
        self.name = pod.metadata.name
        self.container_statuses = pod.status.container_statuses
        self.containers = pod.spec.containers

    def __str__(self):
        return ("CLUSTER_NAME: {cluster_name} "
                "HOST_IP: {host_ip} "
                "NAMESPACE: {namespace} "
                "POD_IP: {pod_ip} "
                "POD_NAME: {pod_name}").format(cluster_name=self.cluster_name,
                                               host_ip=self.host_ip,
                                               namespace=self.namespace,
                                               pod_ip=self.pod_ip,
                                               pod_name=self.name)


class NullPodInfo(PodInfo):

    def __init__(self):
        self.cluster_name = "Fetching data"
        self.namespace = "Fetching data"
        self.name = "Fetching data"
        self.host_ip = "Fetching data"
        self.pod_ip = "Fetching data"
        self.container_statuses = "Fetching data"
        self.containers = "Fetching data"
