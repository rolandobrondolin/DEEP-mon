from bpf_collector import BpfCollector
from bpf_collector import BpfSample
from proc_topology import ProcTopology
from process_info import ProcessInfo
from process_info import SocketProcessItem
import time

topology = ProcTopology()
collector = BpfCollector(topology)

collector.start_capture()
time_to_sleep = 1
while True:
    time.sleep(time_to_sleep)
    start_time = time.time()

    print collector.get_new_sample()

    time_to_sleep = 1 - (time.time() - start_time)
