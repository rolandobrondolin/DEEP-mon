import json


class ContainerInfo:

    def __init__(self, container_id):
        self.container_id = container_id
        self.weighted_cycles = 0
        self.time_ns = 0
        self.power = 0
        self.cpu_usage = 0
        self.pid_set = set()

    def add_weighted_cycles(self, new_cycles):
        self.weighted_cycles = self.weighted_cycles + new_cycles

    def add_time_ns(self, new_time_ns):
        self.time_ns = self.time_ns + new_time_ns

    def add_power(self, new_power):
        self.power = self.power + new_power

    def add_cpu_usage(self, cpu_usage):
        self.cpu_usage = self.cpu_usage + cpu_usage

    def add_pid(self, new_pid):
        self.pid_set.add(new_pid)

    def get_weighted_cycles(self):
        return self.weighted_cycles

    def get_time_ns(self):
        return self.time_ns

    def get_power(self):
        return self.power

    def get_pid_set(self):
        return self.pid_set

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

    def __str__(self):
        return "ID: " + self.container_id \
            + " CYCLES: " + str(self.weighted_cycles) \
            + " TIME_NS: " + str(self.time_ns) \
            + " POWER: " + str(self.power) \
            + " CPU: " + str(self.cpu_usage)
            # + " pids: " + str(self.pid_set)
