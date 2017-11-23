from bpf_collector import BpfCollector
from bpf_collector import BpfSample
from proc_topology import ProcTopology
from process_info import ProcessInfo
from process_info import SocketProcessItem
from sample_controller import SampleController
from process_table import ProcTable
import time

topology = ProcTopology()
collector = BpfCollector(topology)
sample_controller = SampleController(topology.get_hyperthread_count())

process_table = ProcTable()

collector.start_capture(sample_controller.get_timeslice())
time_to_sleep = sample_controller.get_sleep_time()
while True:
    time.sleep(time_to_sleep)
    start_time = time.time()

    sample = collector.get_new_sample(sample_controller)
    #print sample

    process_table.add_process_from_sample(sample)
    for key, value in process_table.proc_table.iteritems():
        print value
    print

    time_to_sleep = sample_controller.get_sleep_time() \
        - (time.time() - start_time)
