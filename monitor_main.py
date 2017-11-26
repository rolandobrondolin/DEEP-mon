from bpf_collector import BpfCollector
from bpf_collector import BpfSample
from proc_topology import ProcTopology
from process_info import ProcessInfo
from process_info import SocketProcessItem
from sample_controller import SampleController
from process_table import ProcTable
from rapl import rapl
import time

topology = ProcTopology()
collector = BpfCollector(topology, False)
sample_controller = SampleController(topology.get_hyperthread_count())

process_table = ProcTable()

collector.start_capture(sample_controller.get_timeslice())
time_to_sleep = sample_controller.get_sleep_time()
rapl_monitor = rapl.RaplMonitor(topology)
while True:

    time.sleep(time_to_sleep)
    start_time = time.time()

    sample = collector.get_new_sample(sample_controller, rapl_monitor)
    # print sample

    # add stuff to cumulative process table
    process_table.add_process_from_sample(sample)

    # for key, value in process_table.proc_table.iteritems():
    #     print value
    # print

    #now, extract containers!
    container_list = process_table.get_container_dictionary()

    for key, value in container_list.iteritems():
        print value
    print

    print sample.get_log_line()

    time_to_sleep = sample_controller.get_sleep_time() \
        - (time.time() - start_time)
