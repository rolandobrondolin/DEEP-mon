"""
    DEEP-mon
    Copyright (C) 2020  Brondolin Rolando

    This file is part of DEEP-mon

    DEEP-mon is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DEEP-mon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import click
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

if __name__ == '__main__':
    from userspace.monitor_main import MonitorMain
    from userspace.curse import Curse
else:
    from .userspace.monitor_main import MonitorMain
    from .userspace.curse import Curse

# Load config file with default values
config = {}
try:
    with open('/home/config.yaml', 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.FullLoader)
except IOError:
    try:
        with open('userspace/default_config.yaml', 'r') as default_config_file:
            config = yaml.load(default_config_file, Loader=yaml.FullLoader)
    except IOError:
        print("Couldn't find a config file, check your path")
        config = {}

CONTEXT_SETTINGS = dict(
    default_map=config
)

@click.command(context_settings=CONTEXT_SETTINGS)
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
def main(window_mode, output_format, debug_mode, net_monitor, nat_trace, print_net_details, dynamic_tcp_client_port_masking, power_measure, memory_measure, disk_measure, file_measure):
    monitor = MonitorMain(output_format, window_mode, debug_mode, net_monitor, nat_trace, print_net_details, dynamic_tcp_client_port_masking, power_measure, memory_measure, disk_measure, file_measure)
    if output_format == 'curses':
        curse = Curse(monitor, power_measure, net_monitor, memory_measure, disk_measure, file_measure)
        curse.start()
    elif output_format == 'console':
        monitor.monitor_loop()

if __name__ == '__main__':
    main()
