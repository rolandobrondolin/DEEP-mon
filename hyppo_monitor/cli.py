from __future__ import print_function

import click
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from monitor_main import MonitorMain


# Load config file with default values
config = {}
try:
    with open('hyppo_monitor/config.yaml', 'r') as config_file:
        config = yaml.load(config_file)
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
def deepmon(kube_config, window_mode, output_format):
    monitor = MonitorMain(output_format, window_mode)
    if output_format == 'snap':
        monitor.snap_monitor_loop()
    else:
        monitor.monitor_loop()
