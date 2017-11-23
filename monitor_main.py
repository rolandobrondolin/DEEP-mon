from bpf_collector import BpfCollector
from bpf_collector import BpfSample
from proc_topology import ProcTopology
from process_info import ProcessInfo
from process_info import SocketProcessItem
from sample_controller import SampleController
from rapl import rapl
import time

topology = ProcTopology()
collector = BpfCollector(topology)

sample_controller = SampleController(topology.get_hyperthread_count())

collector.start_capture(sample_controller.get_timeslice())
time_to_sleep = sample_controller.get_sleep_time()
while True:

    rapl_reader = rapl.RaplReader()
    rapl_sample_start = [ rapl_reader.read_energy_core_sample(str(skt))
            for skt in topology.get_sockets() ]

    time.sleep(time_to_sleep)
    start_time = time.time()

    sample = collector.get_new_sample(sample_controller, rapl_sample_start, rapl_reader)
    print sample

    time_to_sleep = sample_controller.get_sleep_time() \
        - (time.time() - start_time)
