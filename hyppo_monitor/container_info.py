from __future__ import division

import json
import snap_plugin.v1 as snap
import time
from net_collector import TransactionData
from net_collector import TransactionType
import numpy as np
from ddsketch.ddsketch import DDSketch

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
        self.cache_misses = 0
        self.cache_refs = 0
        self.time_ns = 0
        self.power = 0.0
        self.cpu_usage = 0.0
        self.pid_set = set()
        self.timestamp = 0
        self.network_transactions = []
        self.nat_rules = []

        self.tcp_transaction_count = 0
        self.tcp_byte_tx = 0
        self.tcp_byte_rx = 0
        self.tcp_avg_latency = 0
        self.tcp_percentiles = []

        self.http_transaction_count = 0
        self.http_byte_tx = 0
        self.http_byte_rx = 0
        self.http_avg_latency = 0
        self.http_percentiles = []

        self.pct = [50,75,90,99,99.9,99.99,99.999]

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

    def add_cache_misses(self, new_cache_misses):
        self.cache_misses = self.cache_misses + new_cache_misses

    def add_cache_refs(self, new_cache_refs):
        self.cache_refs = self.cache_refs + new_cache_refs

    def add_cpu_usage(self, cpu_usage):
        self.cpu_usage = self.cpu_usage + float(cpu_usage)

    def add_pid(self, new_pid):
        self.pid_set.add(new_pid)

    def add_network_transactions(self, transaction_list):
        self.network_transactions.extend(transaction_list)

    def add_nat_rules(self, nat_list):
        self.nat_rules.extend(nat_list)

    def compute_aggregate_network_metrics(self):
        if self.network_transactions != []:
            http_transactions = DDSketch()
            tcp_transactions = DDSketch()
            for transaction in self.network_transactions:
                if transaction.type == TransactionType.ipv4_http or transaction.type == TransactionType.ipv6_http:
                    self.http_transaction_count = self.http_transaction_count + transaction.get_transaction_count()
                    self.http_byte_rx = self.http_byte_rx + transaction.get_byte_rx()
                    self.http_byte_tx = self.http_byte_tx + transaction.get_byte_tx()
                    self.http_avg_latency = self.http_avg_latency + transaction.get_avg_latency() * transaction.get_transaction_count()
                    http_transactions.merge(transaction.get_samples())
                else:
                    self.tcp_transaction_count = self.tcp_transaction_count + transaction.get_transaction_count()
                    self.tcp_byte_rx = self.tcp_byte_rx + transaction.get_byte_rx()
                    self.tcp_byte_tx = self.tcp_byte_tx + transaction.get_byte_tx()
                    self.tcp_avg_latency = self.tcp_avg_latency + transaction.get_avg_latency() * transaction.get_transaction_count()
                    tcp_transactions.merge(transaction.get_samples())

            if self.http_transaction_count > 0:
                self.http_avg_latency = self.http_avg_latency / float(self.http_transaction_count)
                self.http_percentiles = self.compute_container_percentiles(http_transactions)
            if self.tcp_transaction_count > 0:
                self.tcp_avg_latency = self.tcp_avg_latency / float(self.tcp_transaction_count)
                self.tcp_percentiles = self.compute_container_percentiles(tcp_transactions)

    def compute_container_percentiles(self, latency_sketch):
        out = []
        for p in self.pct:
            out.append(latency_sketch.quantile(p/100))
        return out

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

    def get_cache_misses(self):
        return self.cache_misses

    def get_cache_refs(self):
        return self.cache_refs

    def get_time_ns(self):
        return self.time_ns

    def get_power(self):
        return self.power

    def get_pid_set(self):
        return self.pid_set

    def get_timestamp(self):
        return self.timestamp

    def get_network_transactions(self):
        return self.network_transactions

    def get_rewritten_network_transactions(self):

        for index in range(len(self.network_transactions)):
            transaction = self.network_transactions[index]

            # find if there are nat rules to be added or substituted
            src_modified = False
            dst_modified = False
            for nat_rule in self.nat_rules:
                # start with transaction src and look at both ends of nat rules
                if src_modified == False and nat_rule.get_saddr() == transaction.get_saddr() and nat_rule.get_lport() == transaction.get_lport():
                    # rewrite transaction source
                    transaction.set_saddr(nat_rule.get_daddr())
                    transaction.set_lport(nat_rule.get_dport())
                    src_modified = True
                    # print(nat_rule)
                #
                # if src_modified == False and nat_rule.get_daddr() == transaction.get_saddr() and nat_rule.get_dport() == transaction.get_lport():
                #     # rewrite transaction source
                #     transaction.set_saddr(nat_rule.get_saddr())
                #     transaction.set_lport(nat_rule.get_lport())
                #     src_modified = True
                #     # print(nat_rule)

                # if dst_modified == False and nat_rule.get_saddr() == transaction.get_daddr() and nat_rule.get_lport() == transaction.get_dport():
                #     # rewrite transaction source
                #     transaction.set_daddr(nat_rule.get_daddr())
                #     transaction.set_dport(nat_rule.get_dport())
                #     dst_modified = True
                #     # print(nat_rule)

                if dst_modified == False and nat_rule.get_daddr() == transaction.get_daddr() and nat_rule.get_dport() == transaction.get_dport():
                    # rewrite transaction source
                    transaction.set_daddr(nat_rule.get_saddr())
                    transaction.set_dport(nat_rule.get_lport())
                    dst_modified = True
                    # print(nat_rule)

                if src_modified and dst_modified:
                    break
            self.network_transactions[index] = transaction

        return self.network_transactions


    def get_nat_rules(self):
        return self.nat_rules

    def get_http_percentiles(self):
        return [self.pct, self.http_percentiles]

    def get_tcp_percentiles(self):
        return [self.pct, self.tcp_percentiles]

    def to_dict(self):
        return {'container_id': self.container_id,
                'cycles': self.cycles,
                'weighted_cycles': self.weighted_cycles,
                'instruction_retired': self.instruction_retired,
                'cache_misses': self.cache_misses,
                'cache_refs': self.cache_refs,
                'cycles': self.cycles,
                'time_ns': self.time_ns,
                'power': self.power,
                'cpu_usage': self.cpu_usage,
                'pid_set': self.pid_set
                }

    def to_json(self):
        d = self.to_dict()
        d['pid_set'] = list(d['pid_set'])
        return json.dumps(d, indent=4)

    def _get_perf_summary(self, request_time, snap_namespace):
        perf_summary = {
            "cycles": {"value": self.cycles, "strategy": "sum", "type": "int64"},
            "weighted_cycles": {"value": self.weighted_cycles, "strategy": "sum", "type": "int64"},
            "instructions": {"value": self.instruction_retired, "strategy": "sum", "type": "int64"},
            "cache_misses": {"value": self.cache_misses, "strategy": "sum", "type": "int64"},
            "cache_refs": {"value": self.cache_refs, "strategy": "sum", "type": "int64"},
            "power": {"value": self.power, "strategy": "sum", "type": "double"},
            "time_ns": {"value": self.time_ns, "strategy": "sum", "type": "int64"},
            "cpu": {"value": self.cpu_usage, "strategy": "sum", "type": "double"},
            "thread_count": {"value": len(self.pid_set), "strategy": "sum", "type": "int64"}
        }
        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Performance summary",
            data=json.dumps(perf_summary),
            timestamp=request_time
        )
        return metric


    def _get_net_summary(self, request_time, snap_namespace):
        net_summary = {}
        if self.tcp_transaction_count > 0:
            net_summary["tcp"] = {
                "t_count": {"value": self.tcp_transaction_count, "strategy": "sum", "type": "double"},
                "byte_sent": {"value": self.tcp_byte_tx, "strategy": "sum", "type": "double"},
                "byte_recv": {"value": self.tcp_byte_rx, "strategy": "sum", "type": "double"},
                "avg_lat": {"value": self.tcp_avg_latency, "strategy": "avg", "weight": "t_count", "type": "double"},
                "50p": {"value": self.tcp_percentiles[0], "strategy": "max", "type": "double"},
                "75p": {"value": self.tcp_percentiles[1], "strategy": "max", "type": "double"},
                "90p": {"value": self.tcp_percentiles[2], "strategy": "max", "type": "double"},
                "99p": {"value": self.tcp_percentiles[3], "strategy": "max", "type": "double"},
                "99.9p": {"value": self.tcp_percentiles[4], "strategy": "max", "type": "double"},
                "99.99p": {"value": self.tcp_percentiles[5], "strategy": "max", "type": "double"},
                "99.999p": {"value": self.tcp_percentiles[6], "strategy": "max", "type": "double"}
            }
        if self.http_transaction_count > 0:
            net_summary["http"] = {
                "t_count": {"value": self.http_transaction_count, "strategy": "sum", "type": "double"},
                "byte_sent": {"value": self.http_byte_tx, "strategy": "sum", "type": "double"},
                "byte_recv": {"value": self.http_byte_rx, "strategy": "sum", "type": "double"},
                "avg_lat": {"value": self.http_avg_latency, "strategy": "avg", "weight": "t_count", "type": "double"},
                "50p": {"value": self.http_percentiles[0], "strategy": "max", "type": "double"},
                "75p": {"value": self.http_percentiles[1], "strategy": "max", "type": "double"},
                "90p": {"value": self.http_percentiles[2], "strategy": "max", "type": "double"},
                "99p": {"value": self.http_percentiles[3], "strategy": "max", "type": "double"},
                "99.9p": {"value": self.http_percentiles[4], "strategy": "max", "type": "double"},
                "99.99p": {"value": self.http_percentiles[5], "strategy": "max", "type": "double"},
                "99.999p": {"value": self.http_percentiles[6], "strategy": "max", "type": "double"}
            }

        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Network summary",
            data=json.dumps(net_summary),
            timestamp=request_time
        )
        return metric

    def _get_net_detail(self, request_time, snap_namespace):

        net_detail = []
        for transaction in self.network_transactions:

            # find if there are nat rules to be added or substituted
            src_modified = False
            dst_modified = False
            for nat_rule in self.nat_rules:
                # start with transaction src and look at both ends of nat rules
                if src_modified == False and nat_rule.get_saddr() == transaction.get_saddr() and nat_rule.get_lport() == transaction.get_lport():
                    # rewrite transaction source
                    transaction.set_saddr(nat_rule.get_daddr())
                    transaction.set_lport(nat_rule.get_dport())
                    src_modified = True
                #
                # if src_modified == False and nat_rule.get_daddr() == transaction.get_saddr() and nat_rule.get_dport() == transaction.get_lport():
                #     # rewrite transaction source
                #     transaction.set_saddr(nat_rule.get_saddr())
                #     transaction.set_lport(nat_rule.get_lport())
                #     src_modified = True

                # if dst_modified == False and nat_rule.get_saddr() == transaction.get_daddr() and nat_rule.get_lport() == transaction.get_dport():
                #     # rewrite transaction source
                #     transaction.set_daddr(nat_rule.get_daddr())
                #     transaction.set_dport(nat_rule.get_dport())
                #     dst_modified = True

                if dst_modified == False and nat_rule.get_daddr() == transaction.get_daddr() and nat_rule.get_dport() == transaction.get_dport():
                    # rewrite transaction source
                    transaction.set_daddr(nat_rule.get_saddr())
                    transaction.set_dport(nat_rule.get_lport())
                    dst_modified = True

                if src_modified and dst_modified:
                    break

            net_item = {
                "src_ip": transaction.get_saddr(),
                "src_port": transaction.get_lport(),
                "dst_ip": transaction.get_daddr(),
                "dst_port": transaction.get_dport(),
                "http_path": transaction.get_http_path(),
                "protocol": transaction.get_type_str_no_ip(),
                "role": transaction.get_role_str(),
                "metrics": {
                    "t_count": {"value": transaction.get_transaction_count(), "strategy": "sum", "type": "double"},
                    "byte_sent": {"value": transaction.get_byte_tx(), "strategy": "sum", "type": "double"},
                    "byte_recv": {"value": transaction.get_byte_rx(), "strategy": "sum", "type": "double"},
                    "avg_lat": {"value": transaction.get_avg_latency(), "strategy": "avg", "weight": "t_count", "type": "double"},
                    "50p": {"value": transaction.get_percentiles()[0], "strategy": "max", "type": "double"},
                    "75p": {"value": transaction.get_percentiles()[1], "strategy": "max", "type": "double"},
                    "90p": {"value": transaction.get_percentiles()[2], "strategy": "max", "type": "double"},
                    "99p": {"value": transaction.get_percentiles()[3], "strategy": "max", "type": "double"},
                    "99.9p": {"value": transaction.get_percentiles()[4], "strategy": "max", "type": "double"},
                    "99.99p": {"value": transaction.get_percentiles()[5], "strategy": "max", "type": "double"},
                    "99.999p": {"value": transaction.get_percentiles()[6], "strategy": "max", "type": "double"}
                }
            }

            net_detail.append(net_item)

        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Network detail",
            data=json.dumps(net_detail),
            timestamp=request_time
        )
        return metric

    def to_snap(self, request_time, user_id, hostname, send_net_data):
        metrics_to_be_returned = []

        namespace=[
            snap.NamespaceElement(value="hyppo"),
            snap.NamespaceElement(value="hyppo-monitor"),
            snap.NamespaceElement(value=user_id),
            snap.NamespaceElement(value=hostname),
            snap.NamespaceElement(value="container"),
            snap.NamespaceElement(value=str(self.container_id)),
            snap.NamespaceElement(value="perf_summary")
        ]
        metrics_to_be_returned.append(self._get_perf_summary(request_time, namespace))


        if send_net_data == True and self.http_transaction_count > 0 or self.tcp_transaction_count > 0:
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value=user_id),
                snap.NamespaceElement(value=hostname),
                snap.NamespaceElement(value="container"),
                snap.NamespaceElement(value=str(self.container_id)),
                snap.NamespaceElement(value="net_summary")
            ]
            metrics_to_be_returned.append(self._get_net_summary(request_time, namespace))

            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value=user_id),
                snap.NamespaceElement(value=hostname),
                snap.NamespaceElement(value="container"),
                snap.NamespaceElement(value=str(self.container_id)),
                snap.NamespaceElement(value="net_detail")
            ]
            metrics_to_be_returned.append(self._get_net_detail(request_time, namespace))

        return metrics_to_be_returned


    def __str__(self):
        fmt = '{:<28} {:<32} {:<34} {:<34} {:<34} {:<34} {:<38} {:<30} {:<30}'
        output_line = fmt.format (
                bcolors.BLUE + "ID: " + bcolors.ENDC
                    + self.container_id,
                bcolors.BLUE + "CYCLES: " + bcolors.ENDC
                    + str(self.cycles),
                bcolors.BLUE + "W_CYCLES: " + bcolors.ENDC
                    + str(self.weighted_cycles),
                bcolors.BLUE + "INSTR RET: " + bcolors.ENDC
                    + str(self.instruction_retired),
                bcolors.BLUE + "CACHE MISS: " + bcolors.ENDC
                    + str(self.cache_misses),
                bcolors.BLUE + "CACHE REFS: " + bcolors.ENDC
                    +str(self.cache_refs),
                bcolors.BLUE + "EXEC TIME (s): " + bcolors.ENDC
                    + '{:.5f}'.format(self.time_ns / 1000000000),
                bcolors.BLUE + "CPU USAGE: " + bcolors.ENDC
                    + '{:.3f}'.format(self.cpu_usage),
                bcolors.GREEN + "TOTAL POWER (mW): " + bcolors.ENDC
                    + '{:.3f}'.format(self.power)
                )
        if self.http_transaction_count > 0:
            fmt = '{:<5} {:<32} {:<34} {:<34} {:<34}'
            output_line = output_line + "\n" + fmt.format(
                    bcolors.BLUE + "--->" + bcolors.ENDC,
                    bcolors.BLUE + "HTTP_T_COUNT: " + bcolors.ENDC
                        + str(self.http_transaction_count),
                    bcolors.BLUE + "HTTP_BYTE_SENT: " + bcolors.ENDC
                        + str(self.http_byte_tx),
                    bcolors.BLUE + "HTTP_BYTE_RECV: " + bcolors.ENDC
                        + str(self.http_byte_rx),
                    bcolors.BLUE + "HTTP_AVG_LATENCY (ms): " + bcolors.ENDC
                        + '{:.3f}'.format(self.http_avg_latency)
                    )
            fmt = '{:<5} {:<30} {:<30} {:<30} {:<30} {:<30} {:<30} {:<30}'
            output_line = output_line + "\n" + fmt.format(
                    bcolors.BLUE + "--->" + bcolors.ENDC,
                    bcolors.BLUE + "50p: " + bcolors.ENDC + '{:.5f}'.format(self.http_percentiles[0]),
                    bcolors.BLUE + "75p: " + bcolors.ENDC + '{:.5f}'.format(self.http_percentiles[1]),
                    bcolors.BLUE + "90p: " + bcolors.ENDC + '{:.5f}'.format(self.http_percentiles[2]),
                    bcolors.BLUE + "99p: " + bcolors.ENDC + '{:.5f}'.format(self.http_percentiles[3]),
                    bcolors.BLUE + "99.9p: " + bcolors.ENDC + '{:.5f}'.format(self.http_percentiles[4]),
                    bcolors.BLUE + "99.99p: " + bcolors.ENDC + '{:.5f}'.format(self.http_percentiles[5]),
                    bcolors.BLUE + "99.999p: " + bcolors.ENDC + '{:.5f}'.format(self.http_percentiles[6]),
            )

        if self.tcp_transaction_count > 0:
            fmt = '{:<5} {:<32} {:<34} {:<34} {:<34}'
            output_line = output_line + "\n" + fmt.format(
                    bcolors.BLUE + "--->" + bcolors.ENDC,
                    bcolors.BLUE + "TCP_T_COUNT: " + bcolors.ENDC
                        + str(self.tcp_transaction_count),
                    bcolors.BLUE + "TCP_BYTE_SENT: " + bcolors.ENDC
                        + str(self.tcp_byte_tx),
                    bcolors.BLUE + "TCP_BYTE_RECV: " + bcolors.ENDC
                        + str(self.tcp_byte_rx),
                    bcolors.BLUE + "TCP_AVG_LATENCY (ms): " + bcolors.ENDC
                        + '{:.3f}'.format(self.tcp_avg_latency)
                    )
            fmt = '{:<5} {:<30} {:<30} {:<30} {:<30} {:<30} {:<30} {:<30}'
            output_line = output_line + "\n" + fmt.format(
                    bcolors.BLUE + "--->" + bcolors.ENDC,
                    bcolors.BLUE + "50p: " + bcolors.ENDC + '{:.5f}'.format(self.tcp_percentiles[0]),
                    bcolors.BLUE + "75p: " + bcolors.ENDC + '{:.5f}'.format(self.tcp_percentiles[1]),
                    bcolors.BLUE + "90p: " + bcolors.ENDC + '{:.5f}'.format(self.tcp_percentiles[2]),
                    bcolors.BLUE + "99p: " + bcolors.ENDC + '{:.5f}'.format(self.tcp_percentiles[3]),
                    bcolors.BLUE + "99.9p: " + bcolors.ENDC + '{:.5f}'.format(self.tcp_percentiles[4]),
                    bcolors.BLUE + "99.99p: " + bcolors.ENDC + '{:.5f}'.format(self.tcp_percentiles[5]),
                    bcolors.BLUE + "99.999p: " + bcolors.ENDC + '{:.5f}'.format(self.tcp_percentiles[6]),
            )
        return output_line
