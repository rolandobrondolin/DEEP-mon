from __future__ import print_function
from bpf_collector import BpfCollector
from proc_topology import ProcTopology
from sample_controller import SampleController
from process_table import ProcTable
from k8s_client.k8s_client import K8SClient
from rapl import rapl
import time
import os.path
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


topology = ProcTopology()
collector = BpfCollector(topology, False)
sample_controller = SampleController(topology.get_hyperthread_count())

process_table = ProcTable()

collector.start_capture(sample_controller.get_timeslice())
time_to_sleep = sample_controller.get_sleep_time()
rapl_monitor = rapl.RaplMonitor(topology)

try:
    with open('config.yaml', 'r') as stream:
        conf = yaml.load(stream)
        kube_conf = os.path.expanduser(conf.get('kube_conf'))
        k8s_api = K8SClient(kube_conf)
except IOError:
    k8s_api = None


while True:

    time.sleep(time_to_sleep)
    start_time = time.time()

    sample = collector.get_new_sample(sample_controller, rapl_monitor)

    # add stuff to cumulative process table
    process_table.add_process_from_sample(sample)

    # Now, extract containers!
    container_list = process_table.get_container_dictionary()

    for key, value in container_list.iteritems():
        if(value.container_id.find("idle") == -1 and
                value.container_id.find("others") == -1):
            if k8s_api:
                pod = k8s_api.get_container_pod(value)
                print(pod)
        print(value)
    print

    print(sample.get_log_line())

    time_to_sleep = sample_controller.get_sleep_time() \
        - (time.time() - start_time)
    print(time_to_sleep)
