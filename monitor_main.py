from __future__ import print_function
import argparse
import time
from bpf_collector import BpfCollector
from proc_topology import ProcTopology
from sample_controller import SampleController
from process_table import ProcTable
from rapl import rapl

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--format", type=str,
                    help="Output format", required=False)
args = parser.parse_args()
output_format = args.format


topology = ProcTopology()
collector = BpfCollector(topology, False)
sample_controller = SampleController(topology.get_hyperthread_count())

process_table = ProcTable()

collector.start_capture(sample_controller.get_timeslice())
time_to_sleep = sample_controller.get_sleep_time()
rapl_monitor = rapl.RaplMonitor(topology)


while True:

    initial_rapl_sample = {
            "package": rapl_monitor.take_sample_package(),
            "core": rapl_monitor.take_sample_core(),
            "dram": rapl_monitor.take_sample_dram()
            }

    time.sleep(time_to_sleep)
    start_time = time.time()

    bpf_sample = collector.get_new_sample(sample_controller,
                                          rapl_monitor,
                                          initial_rapl_sample)

    # add stuff to cumulative process table
    process_table.add_process_from_sample(bpf_sample)

    # Now, extract containers!
    container_list = process_table.get_container_dictionary()

    if output_format == "json":
        for key, value in container_list.iteritems():
            print(value.to_json())
        print(bpf_sample.get_log_json())
        print()
    else:
        for key, value in container_list.iteritems():
            print(value)
        print(bpf_sample.get_log_line())
        print()

    time_to_sleep = sample_controller.get_sleep_time() \
        - (time.time() - start_time)
