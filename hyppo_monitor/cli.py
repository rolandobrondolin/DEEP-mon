import click
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from .monitor_main import MonitorMain
from .curse import Curse


# Load config file with default values
config = {}
try:
    with open('hyppo_monitor/config.yaml', 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.FullLoader)
except IOError:
    print("Couldn't find a config file, check your path")
    config = {}

CONTEXT_SETTINGS = dict(
    default_map=config
)

@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('--kube-config', '-c')
@click.option('--window-mode', '-w')
@click.option('--output-format', '-o')
@click.option('--debug-mode', '-d')
@click.option('--net_monitor', '-n')
@click.option('--nat_trace')
@click.option('--print_net_details')
@click.option('--dynamic_tcp_client_port_masking')
@click.option('--power_measure')
@click.option('--memory_measure')
@click.option('--disk_measure')
@click.option('--file_measure')
def deepmon(kube_config, window_mode, output_format, debug_mode, net_monitor, nat_trace, print_net_details, dynamic_tcp_client_port_masking, power_measure, memory_measure, disk_measure, file_measure):
    monitor = MonitorMain(output_format, window_mode, debug_mode, net_monitor, nat_trace, print_net_details, dynamic_tcp_client_port_masking, power_measure, memory_measure, disk_measure, file_measure)
    if output_format == 'snap':
        monitor.snap_monitor_loop()
    # Comment out the following elif to go back to the old console display mode
    elif output_format == 'console':
        curse = Curse(monitor, power_measure, net_monitor, memory_measure, disk_measure, file_measure)
        curse.start()
    else:
        monitor.monitor_loop()
