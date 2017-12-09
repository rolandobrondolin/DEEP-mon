import json
import snap_plugin.v1 as snap
import time

class ContainerInfo:

    def __init__(self, container_id):
        self.container_id = container_id
        self.weighted_cycles = 0
        self.instruction_retired = 0
        self.time_ns = 0
        self.power = 0
        self.cpu_usage = 0
        self.pid_set = set()
        self.timestamp = 0

    def add_weighted_cycles(self, new_cycles):
        self.weighted_cycles = self.weighted_cycles + new_cycles

    def add_time_ns(self, new_time_ns):
        self.time_ns = self.time_ns + new_time_ns

    def add_power(self, new_power):
        self.power = self.power + new_power

    def add_instructions(self, new_instructions):
        self.instruction_retired = self.instruction_retired + new_instructions

    def add_cpu_usage(self, cpu_usage):
        self.cpu_usage = self.cpu_usage + cpu_usage

    def add_pid(self, new_pid):
        self.pid_set.add(new_pid)

    def set_timestamp(self, ts):
        self.timestamp = ts

    def set_last_ts(self, ts):
        if(self.timestamp < ts):
            self.timestamp = ts

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


    def to_snap(self, request_time):
        metrics_to_be_returned = []

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=self.container_id),
            snap.NamespaceElement(value="ID")
        ]
        metrics_to_be_returned.append(self._get_snap_container_id(request_time, namespace))

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=self.container_id),
            snap.NamespaceElement(value="cycles")
        ]
        metrics_to_be_returned.append(self._get_snap_cycles(request_time, namespace))

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=self.container_id),
            snap.NamespaceElement(value="instructions")
        ]
        metrics_to_be_returned.append(self._get_snap_instructions(request_time, namespace))

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=self.container_id),
            snap.NamespaceElement(value="power")
        ]
        metrics_to_be_returned.append(self._get_snap_power(request_time, namespace))

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=self.container_id),
            snap.NamespaceElement(value="cpu")
        ]
        metrics_to_be_returned.append(self._get_snap_cpu(request_time, namespace))

        return metrics_to_be_returned


    def __str__(self):
        return "ID: " + self.container_id \
            + " CYCLES: " + str(self.weighted_cycles) \
            + " INSTR: " + str(self.instruction_retired) \
            + " TIME_NS: " + str(self.time_ns) \
            + " POWER: " + str(self.power) \
            + " CPU: " + str(self.cpu_usage)
            # + " pids: " + str(self.pid_set)
