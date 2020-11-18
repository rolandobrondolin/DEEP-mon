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

import ctypes as ct
from .net_collector import TransactionData
import json


class BpfPidStatus(ct.Structure):
    TASK_COMM_LEN = 16
    socket_size = 0
    _fields_ = [("pid", ct.c_int),
                ("tgid", ct.c_int),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("weighted_cycles", ct.c_ulonglong * 2 * socket_size),
                ("cycles", ct.c_ulonglong * 2),
                ("instruction_retired", ct.c_ulonglong * 2),
                ("cache_misses", ct.c_ulonglong * 2),
                ("cache_refs", ct.c_ulonglong * 2),
                ("time_ns", ct.c_ulonglong * 2),
                ("bpf_selector", ct.c_int),
                ("ts", ct.c_ulonglong * 2 * socket_size)]

    def __init__(self, socket_size):
        self.socket_size = socket_size

class SocketProcessItem:

    def __init__(self, weighted_cycles = 0, ts = 0):
        self.weighted_cycles = weighted_cycles
        self.ts = ts

    def set_weighted_cycles(self, weighted_cycles):
        self.weighted_cycles = weighted_cycles

    def set_ts(self, ts):
        self.ts = ts

    def get_weighted_cycles(self):
        return self.weighted_cycles

    def get_ts(self):
        return self.ts

    def reset(self):
        self.weighted_cycles = 0
        self.ts = 0

    def __str__(self):
        return "ts: " + str(self.ts) \
            + " w:" + str(self.weighted_cycles)

class ProcessInfo:

    def __init__(self, num_sockets):
        self.pid = -1
        self.tgid = -1
        self.comm = ""
        self.power = 0.0
        self.cpu_usage = 0.0
        self.socket_data = []
        self.cgroup_id = ""
        self.container_id = ""

        self.instruction_retired = 0
        self.cycles = 0
        self.cache_misses = 0
        self.cache_refs = 0
        self.time_ns = 0

        self.network_transactions = []
        self.nat_rules = []

        for i in range(0, num_sockets):
            self.socket_data.append(SocketProcessItem())

    def set_pid(self, pid):
        self.pid = pid

    def set_tgid(self, tgid):
        self.tgid = tgid

    def set_comm(self, comm):
        self.comm = comm

    def set_power(self, power):
        self.power = float(power)

    def set_cpu_usage(self, cpu_usage):
        self.cpu_usage = float(cpu_usage)

    def set_instruction_retired(self, instruction_retired):
        self.instruction_retired = instruction_retired

    def set_cycles(self, cycles):
        self.cycles = cycles

    def set_cache_misses(self, cache_misses):
        self.cache_misses = cache_misses

    def set_cache_refs(self, cache_refs):
        self.cache_refs = cache_refs

    def set_time_ns(self, time_ns):
        self.time_ns = time_ns

    def compute_cpu_usage_millis(self, total_execution_time_millis, total_cores):
        self.cpu_usage = float((self.time_ns/1000000) \
            / total_execution_time_millis * total_cores * 100) # percentage moved to other percentage

    def set_socket_data_array(self, socket_data_array):
        self.socket_data = socket_data_array

    def set_socket_data(self, socket_index, socket_data):
        self.socket_data[socket_index] = socket_data

    def set_raw_socket_data(self, socket_index, weighted_cycles, ts):
        self.socket_data[socket_index] = \
            SocketProcessItem(weighted_cycles, instruction_retired, time_ns, ts)

    def set_cgroup_id(self, cgroup_id):
        self.cgroup_id = cgroup_id

    def set_container_id(self, container_id):
        self.container_id = container_id

    def set_network_transactions(self, network_transactions):
        self.network_transactions = network_transactions

    def set_nat_rules(self, nat_rules):
        self.nat_rules = nat_rules


    def reset_data(self):
        self.instruction_retired = 0
        self.cycles = 0
        self.cache_misses = 0
        self.time_ns = 0
        self.network_transactions = []
        self.nat_rules = []
        for item in self.socket_data:
            item.reset()

    def get_pid(self):
        return self.pid

    def get_tgid(self):
        return self.tgid

    def get_comm(self):
        return self.comm

    def get_power(self):
        return self.power

    def get_cpu_usage(self):
        return self.cpu_usage

    def get_instruction_retired(self):
        return self.instruction_retired

    def get_cycles(self):
        return self.cycles

    def get_cache_misses(self):
        return self.cache_misses

    def get_cache_refs(self):
        return self.cache_refs

    def get_time_ns(self):
        return self.time_ns

    def get_socket_data(self, socket_index = -1):
        if socket_index < 0:
            return self.socket_data
        return self.socket_data[socket_index]

    def get_cgroup_id(self):
        return self.cgroup_id

    def get_container_id(self):
        return self.container_id

    def get_aggregated_weighted_cycles(self):
        aggregated = 0
        for item in self.socket_data:
            aggregated = aggregated + item.get_weighted_cycles()
        return aggregated

    def get_last_ts(self):
        max_ts = 0
        for item in self.socket_data:
            if max_ts < item.get_ts():
                max_ts = item.get_ts()
        return max_ts

    def get_network_transactions(self):
        return self.network_transactions

    def get_nat_rules(self):
        return self.nat_rules


    def __str__(self):
        str_rep = str(self.pid) + " comm: " + str(self.comm) \
            + " c_id: " + self.container_id + " p: " + str(self.power) \
            + " u: " + str(self.cpu_usage)

        for socket_item in self.socket_data:
            str_rep = str_rep + " " + str(socket_item)

        return str_rep
