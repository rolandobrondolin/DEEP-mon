from __future__ import print_function
from k8s_client.k8s_client import K8SClient
import os.path
import time
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

try:
    with open('config.yaml', 'r') as stream:
        conf = yaml.load(stream)
        kube_conf = os.path.expanduser(conf.get('kube_conf'))
        k8s_api = K8SClient(kube_conf)
except IOError:
    k8s_api = None

while True:
    if k8s_api:
        pods = k8s_api.get_all_pods()
        for pod in pods.items:
            print(pod)
        print()
    time.sleep(3)
