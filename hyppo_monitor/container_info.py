from __future__ import division

import json
import snap_plugin.v1 as snap
import time

class bcolors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ContainerInfo:

    def __init__(self, container_id):
        self.container_id = container_id
        self.cycles = 0
        self.weighted_cycles = 0
        self.instruction_retired = 0
        self.time_ns = 0
        self.power = 0.0
        self.cpu_usage = 0.0
        self.pid_set = set()
        self.timestamp = 0

    def add_weighted_cycles(self, new_cycles):
        self.weighted_cycles = self.weighted_cycles + new_cycles

    def add_cycles(self, new_cycles):
        self.cycles = self.cycles + new_cycles

    def add_time_ns(self, new_time_ns):
        self.time_ns = self.time_ns + new_time_ns

    def add_power(self, new_power):
        self.power = self.power + float(new_power)

    def add_instructions(self, new_instructions):
        self.instruction_retired = self.instruction_retired + new_instructions

    def add_cpu_usage(self, cpu_usage):
        self.cpu_usage = self.cpu_usage + float(cpu_usage)

    def add_pid(self, new_pid):
        self.pid_set.add(new_pid)

    def set_timestamp(self, ts):
        self.timestamp = ts

    def set_last_ts(self, ts):
        if(self.timestamp < ts):
            self.timestamp = ts

    def get_cycles(self):
        return self.cycles

    def get_weighted_cycles(self):
        return self.weighted_cycles

    def get_instruction_retired(self):
        return self.instruction_retired

    def get_time_ns(self):
        return self.time_ns

    def get_power(self):
        return self.power

    def get_pid_set(self):
        return self.pid_set

    def get_timestamp(self):
        return self.timestamp

    def to_dict(self):
        return {'container_id': self.container_id,
                'cycles': self.cycles,
                'weighted_cycles': self.weighted_cycles,
                'time_ns': self.time_ns,
                'power': self.power,
                'cpu_usage': self.cpu_usage,
                'pid_set': self.pid_set
                }

    def to_json(self):
        d = self.to_dict()
        d['pid_set'] = list(d['pid_set'])
        return json.dumps(d, indent=4)

    def _get_snap_container_id(self, request_time, snap_namespace):
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Container ID",
            data=self.container_id,
            timestamp=request_time
        )
        return metric

    def _get_snap_cycles(self, request_time, snap_namespace):
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Cycles",
            data=self.cycles,
            timestamp=request_time
        )
        return metric

    def _get_snap_weighted_cycles(self, request_time, snap_namespace):
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Weighted cycles",
            data=self.weighted_cycles,
            timestamp=request_time
        )
        return metric

    def _get_snap_instructions(self, request_time, snap_namespace):
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Thread instruction retired",
            data=self.instruction_retired,
            timestamp=request_time
        )
        return metric

    def _get_snap_power(self, request_time, snap_namespace):
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Total active power in watt",
            data=self.power,
            timestamp=request_time
        )
        return metric

    def _get_snap_cpu(self, request_time, snap_namespace):
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Total cpu usage",
            data=self.cpu_usage,
            timestamp=request_time
        )
        return metric

    def _get_time_ns(self, request_time, snap_namespace):
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Total execution time",
            data=self.time_ns,
            timestamp=request_time
        )
        return metric


    def to_snap(self, request_time, user_id, hostname):
        metrics_to_be_returned = []

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value=user_id),
            snap.NamespaceElement(value=hostname),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=str(self.container_id)),
            snap.NamespaceElement(value="cycles")
        ]
        metrics_to_be_returned.append(self._get_snap_cycles(request_time, namespace))

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value=user_id),
            snap.NamespaceElement(value=hostname),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=str(self.container_id)),
            snap.NamespaceElement(value="weighted_cycles")
        ]
        metrics_to_be_returned.append(self._get_snap_weighted_cycles(request_time, namespace))

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value=user_id),
            snap.NamespaceElement(value=hostname),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=str(self.container_id)),
            snap.NamespaceElement(value="instructions")
        ]
        metrics_to_be_returned.append(self._get_snap_instructions(request_time, namespace))

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value=user_id),
            snap.NamespaceElement(value=hostname),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=str(self.container_id)),
            snap.NamespaceElement(value="power")
        ]
        metrics_to_be_returned.append(self._get_snap_power(request_time, namespace))

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value=user_id),
            snap.NamespaceElement(value=hostname),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=str(self.container_id)),
            snap.NamespaceElement(value="cpu")
        ]
        metrics_to_be_returned.append(self._get_snap_cpu(request_time, namespace))

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value=user_id),
            snap.NamespaceElement(value=hostname),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=str(self.container_id)),
            snap.NamespaceElement(value="time_ns")
        ]
        metrics_to_be_returned.append(self._get_time_ns(request_time, namespace))

        return metrics_to_be_returned


    def __str__(self):
        fmt = '{:<28} {:<32} {:<34} {:<34} {:<38} {:<30}'
        output_line = fmt.format (
                bcolors.BLUE + "ID: " + bcolors.ENDC
                    + self.container_id,
                bcolors.BLUE + "CYCLES: " + bcolors.ENDC
                    + str(self.cycles),
                bcolors.BLUE + "W_CYCLES: " + bcolors.ENDC
                    + str(self.weighted_cycles),
                bcolors.BLUE + "INSTR RET: " + bcolors.ENDC
                    + str(self.instruction_retired),
                bcolors.BLUE + "EXEC TIME (s): " + bcolors.ENDC
                    + '{:.5f}'.format(self.time_ns / 1000000000),
                bcolors.GREEN + "TOTAL POWER (mW): " + bcolors.ENDC
                    + '{:.3f}'.format(self.power),
                bcolors.BLUE + "CPU USAGE: " + bcolors.ENDC
                    + '{:.3f}'.format(self.cpu_usage)
                )
        return output_line
