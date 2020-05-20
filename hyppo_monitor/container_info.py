from __future__ import division

import json
import snap_plugin.v1 as snap
import time
from net_collector import TransactionData
from net_collector import TransactionType
from net_collector import TransactionRole
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

        #memory metrics
        self.mem_RSS = 0
        self.mem_PSS = 0
        self.mem_USS = 0
        #disk metrics
        self.kb_r = 0
        self.kb_w = 0
        self.num_r = 0
        self.num_w = 0
        self.disk_avg_lat = 0

        self.tcp_transaction_count = 0
        self.tcp_transaction_count_client = 0
        self.tcp_transaction_count_server = 0
        self.tcp_byte_tx = 0
        self.tcp_byte_rx = 0
        self.tcp_avg_latency = 0
        self.tcp_avg_latency_client = 0
        self.tcp_avg_latency_server = 0
        self.tcp_percentiles = []
        self.tcp_percentiles_client = []
        self.tcp_percentiles_server = []

        self.http_transaction_count = 0
        self.http_transaction_count_client = 0
        self.http_transaction_count_server = 0
        self.http_byte_tx = 0
        self.http_byte_rx = 0
        self.http_avg_latency = 0
        self.http_avg_latency_client = 0
        self.http_avg_latency_server = 0
        self.http_percentiles = []
        self.http_percentiles_client = []
        self.http_percentiles_server = []

        self.pct = [50,75,90,99,99.9,99.99,99.999]

        self.network_threads = 0
        self.weighted_threads = 0
        self.weighted_cpus = []

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
        self.add_weighted_cpu_usage(cpu_usage)

    def add_pid(self, new_pid):
        self.pid_set.add(new_pid)

    def add_network_transactions(self, transaction_list):
        self.network_transactions.extend(transaction_list)
        self.network_threads = self.network_threads + 1

    def add_nat_rules(self, nat_list):
        self.nat_rules.extend(nat_list)

    def set_mem_RSS(self, rss):
        self.mem_RSS = rss
    
    def set_mem_PSS(self, pss):
        self.mem_PSS = pss

    def set_mem_USS(self, uss):
        self.mem_USS = uss

    def set_disk_kb_r(self, kb_r):
        self.kb_r = kb_r

    def set_disk_kb_w(self, kb_w):
        self.kb_w = kb_w

    def set_disk_num_r(self, num_r):
        self.num_r = num_r

    def set_disk_num_w(self, num_w):
        self.num_w = num_w

    def set_disk_avg_lat(self, avg_lat):
        self.disk_avg_lat = avg_lat

    def add_weighted_cpu_usage(self, cpu_usage):
        self.weighted_cpus.append(cpu_usage)
        max = 0
        #compute max
        for usage in self.weighted_cpus:
            if max < usage:
                max = usage

        # how many max do we have here?
        maxes = 0
        bin = 0
        for usage in self.weighted_cpus:
            bin = bin + usage
            if bin >= max:
                maxes = maxes + 1
                bin = bin - max

        self.weighted_threads = maxes

    def compute_aggregate_network_metrics(self):
        if self.network_transactions != []:
            http_transactions = DDSketch()
            http_transactions_client = DDSketch()
            http_transactions_server = DDSketch()
            tcp_transactions = DDSketch()
            tcp_transactions_client = DDSketch()
            tcp_transactions_server = DDSketch()

            for transaction in self.network_transactions:
                if transaction.type == TransactionType.ipv4_http or transaction.type == TransactionType.ipv6_http:
                    self.http_transaction_count = self.http_transaction_count + transaction.get_transaction_count()
                    self.http_byte_rx = self.http_byte_rx + transaction.get_byte_rx()
                    self.http_byte_tx = self.http_byte_tx + transaction.get_byte_tx()
                    self.http_avg_latency = self.http_avg_latency + transaction.get_avg_latency() * transaction.get_transaction_count()
                    http_transactions.merge(transaction.get_samples())

                    if transaction.role == TransactionRole.client:
                        self.http_transaction_count_client = self.http_transaction_count_client + transaction.get_transaction_count()
                        self.http_avg_latency_client = self.http_avg_latency_client + transaction.get_avg_latency() * transaction.get_transaction_count()
                        http_transactions_client.merge(transaction.get_samples())
                    else:
                        self.http_transaction_count_server = self.http_transaction_count_server + transaction.get_transaction_count()
                        self.http_avg_latency_server = self.http_avg_latency_server + transaction.get_avg_latency() * transaction.get_transaction_count()
                        http_transactions_server.merge(transaction.get_samples())

                else:
                    self.tcp_transaction_count = self.tcp_transaction_count + transaction.get_transaction_count()
                    self.tcp_byte_rx = self.tcp_byte_rx + transaction.get_byte_rx()
                    self.tcp_byte_tx = self.tcp_byte_tx + transaction.get_byte_tx()
                    self.tcp_avg_latency = self.tcp_avg_latency + transaction.get_avg_latency() * transaction.get_transaction_count()
                    tcp_transactions.merge(transaction.get_samples())

                    if transaction.role == TransactionRole.client:
                        self.tcp_transaction_count_client = self.tcp_transaction_count_client + transaction.get_transaction_count()
                        self.tcp_avg_latency_client = self.tcp_avg_latency_client + transaction.get_avg_latency() * transaction.get_transaction_count()
                        tcp_transactions_client.merge(transaction.get_samples())
                    else:
                        self.tcp_transaction_count_server = self.tcp_transaction_count_server + transaction.get_transaction_count()
                        self.tcp_avg_latency_server = self.tcp_avg_latency_server + transaction.get_avg_latency() * transaction.get_transaction_count()
                        tcp_transactions_server.merge(transaction.get_samples())

            if self.http_transaction_count > 0:
                self.http_avg_latency = self.http_avg_latency / float(self.http_transaction_count)
                self.http_percentiles = self.compute_container_percentiles(http_transactions)

                if self.http_transaction_count_client > 0:
                    self.http_avg_latency_client = self.http_avg_latency_client / float(self.http_transaction_count_client)
                    self.http_percentiles_client = self.compute_container_percentiles(http_transactions_client)
                if self.http_transaction_count_server > 0:
                    self.http_avg_latency_server = self.http_avg_latency_server / float(self.http_transaction_count_server)
                    self.http_percentiles_server = self.compute_container_percentiles(http_transactions_server)

            if self.tcp_transaction_count > 0:
                self.tcp_avg_latency = self.tcp_avg_latency / float(self.tcp_transaction_count)
                self.tcp_percentiles = self.compute_container_percentiles(tcp_transactions)

                if self.tcp_transaction_count_client > 0:
                    self.tcp_avg_latency_client = self.tcp_avg_latency_client / float(self.tcp_transaction_count_client)
                    self.tcp_percentiles_client = self.compute_container_percentiles(tcp_transactions_client)
                if self.tcp_transaction_count_server > 0:
                    self.tcp_avg_latency_server = self.tcp_avg_latency_server / float(self.tcp_transaction_count_server)
                    self.tcp_percentiles_server = self.compute_container_percentiles(tcp_transactions_server)

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
        
    def get_cpu_usage(self):
        return self.cpu_usage

    def get_pid_set(self):
        return self.pid_set

    def get_timestamp(self):
        return self.timestamp

    def get_network_transactions(self):
        return self.network_transactions

    def get_mem_RSS(self):
        return self.mem_RSS
    
    def get_mem_PSS(self):
        return self.mem_PSS
    
    def get_mem_USS(self):
        return self.mem_USS

    def get_kb_r(self):
        return self.kb_r
    
    def get_kb_w(self):
        return self.kb_w
    
    def get_num_r(self):
        return self.num_r
    
    def get_num_w(self):
        return self.num_w
    
    def get_disk_avg_lat(self):
        return self.disk_avg_lat

    def get_http_transaction_count(self):
        return self.http_transaction_count

    def get_http_byte_tx(self):
        return self.http_byte_tx

    def get_http_byte_rx(self):
        return self.http_byte_rx

    def get_http_avg_latency(self):
        return self.http_avg_latency

    def get_tcp_transaction_count(self):
        return self.tcp_transaction_count

    def get_tcp_byte_tx(self):
        return self.tcp_byte_tx

    def get_tcp_byte_rx(self):
        return self.tcp_byte_rx

    def get_tcp_avg_latency(self):
        return self.tcp_avg_latency

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
            "thread_count": {"value": len(self.pid_set), "strategy": "sum", "type": "int64"},
            "network_threads": {"value": self.network_threads, "strategy": "sum", "type": "int64"},
            "weighted_threads": {"value": self.weighted_threads, "strategy": "sum", "type": "int64"}
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

            if self.tcp_transaction_count_client > 0:

                client_tcp = {
                    "t_count_client": {"value": self.tcp_transaction_count_client, "strategy": "sum", "type": "double"},
                    "avg_lat_client": {"value": self.tcp_avg_latency_client, "strategy": "avg", "weight": "t_count", "type": "double"},
                    "50p_client": {"value": self.tcp_percentiles_client[0], "strategy": "max", "type": "double"},
                    "75p_client": {"value": self.tcp_percentiles_client[1], "strategy": "max", "type": "double"},
                    "90p_client": {"value": self.tcp_percentiles_client[2], "strategy": "max", "type": "double"},
                    "99p_client": {"value": self.tcp_percentiles_client[3], "strategy": "max", "type": "double"},
                    "99.9p_client": {"value": self.tcp_percentiles_client[4], "strategy": "max", "type": "double"},
                    "99.99p_client": {"value": self.tcp_percentiles_client[5], "strategy": "max", "type": "double"},
                    "99.999p_client": {"value": self.tcp_percentiles_client[6], "strategy": "max", "type": "double"}
                }

                net_summary["tcp"].update(client_tcp)

            if self.tcp_transaction_count_server > 0:

                server_tcp = {
                    "t_count_server": {"value": self.tcp_transaction_count_server, "strategy": "sum", "type": "double"},
                    "avg_lat_server": {"value": self.tcp_avg_latency_server, "strategy": "avg", "weight": "t_count", "type": "double"},
                    "50p_server": {"value": self.tcp_percentiles_server[0], "strategy": "max", "type": "double"},
                    "75p_server": {"value": self.tcp_percentiles_server[1], "strategy": "max", "type": "double"},
                    "90p_server": {"value": self.tcp_percentiles_server[2], "strategy": "max", "type": "double"},
                    "99p_server": {"value": self.tcp_percentiles_server[3], "strategy": "max", "type": "double"},
                    "99.9p_server": {"value": self.tcp_percentiles_server[4], "strategy": "max", "type": "double"},
                    "99.99p_server": {"value": self.tcp_percentiles_server[5], "strategy": "max", "type": "double"},
                    "99.999p_server": {"value": self.tcp_percentiles_server[6], "strategy": "max", "type": "double"}
                }

                net_summary["tcp"].update(server_tcp)

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

            if self.http_transaction_count_client > 0:

                client_http = {
                    "t_count_client": {"value": self.http_transaction_count_client, "strategy": "sum", "type": "double"},
                    "avg_lat_client": {"value": self.http_avg_latency_client, "strategy": "avg", "weight": "t_count", "type": "double"},
                    "50p_client": {"value": self.http_percentiles_client[0], "strategy": "max", "type": "double"},
                    "75p_client": {"value": self.http_percentiles_client[1], "strategy": "max", "type": "double"},
                    "90p_client": {"value": self.http_percentiles_client[2], "strategy": "max", "type": "double"},
                    "99p_client": {"value": self.http_percentiles_client[3], "strategy": "max", "type": "double"},
                    "99.9p_client": {"value": self.http_percentiles_client[4], "strategy": "max", "type": "double"},
                    "99.99p_client": {"value": self.http_percentiles_client[5], "strategy": "max", "type": "double"},
                    "99.999p_client": {"value": self.http_percentiles_client[6], "strategy": "max", "type": "double"}
                }
                net_summary["http"].update(client_http)

            if self.http_transaction_count_server > 0:

                server_http = {
                    "t_count_server": {"value": self.http_transaction_count_server, "strategy": "sum", "type": "double"},
                    "avg_lat_server": {"value": self.http_avg_latency_server, "strategy": "avg", "weight": "t_count", "type": "double"},
                    "50p_server": {"value": self.http_percentiles_server[0], "strategy": "max", "type": "double"},
                    "75p_server": {"value": self.http_percentiles_server[1], "strategy": "max", "type": "double"},
                    "90p_server": {"value": self.http_percentiles_server[2], "strategy": "max", "type": "double"},
                    "99p_server": {"value": self.http_percentiles_server[3], "strategy": "max", "type": "double"},
                    "99.9p_server": {"value": self.http_percentiles_server[4], "strategy": "max", "type": "double"},
                    "99.99p_server": {"value": self.http_percentiles_server[5], "strategy": "max", "type": "double"},
                    "99.999p_server": {"value": self.http_percentiles_server[6], "strategy": "max", "type": "double"}
                }

                net_summary["http"].update(server_http)

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

    def _get_mem_summary(self, request_time, snap_namespace):
        mem_summary = {
            "RSS": {"value": self.mem_RSS, "strategy": "sum", "type": "int64"},
            "PSS": {"value": self.mem_PSS, "strategy": "sum", "type": "int64"},
            "USS": {"value": self.mem_USS, "strategy": "sum", "type": "int64"}
        }

        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Memory summary",
            data=json.dumps(mem_summary),
            timestamp=request_time
        )
        return metric

    def _get_disk_summary(self, request_time, snap_namespace):
        disk_summary = {
            "kb_r": {"value": self.kb_r, "strategy": "sum", "type": "int64"},
            "kb_w": {"value": self.kb_w, "strategy": "sum", "type": "int64"},
            "num_r": {"value": self.num_r, "strategy": "sum", "type": "int64"},
            "num_w": {"value": self.num_w, "strategy": "sum", "type": "int64"},
            "avg_lat": {"value": self.disk_avg_lat, "strategy": "avg", "weight": "num_r", "type": "double"}
        }

        metric = snap.Metric(
            namespace=snap_namespace,
            version=1,
            description="Disk summary",
            data=json.dumps(disk_summary),
            timestamp=request_time
        )
        return metric

    def to_snap(self, request_time, user_id, hostname, send_net_data, send_mem_data=False, send_disk_data=False):
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

        if send_mem_data and self.mem_RSS > 0:
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value=user_id),
                snap.NamespaceElement(value=hostname),
                snap.NamespaceElement(value="container"),
                snap.NamespaceElement(value=str(self.container_id)),
                snap.NamespaceElement(value="mem_summary")
            ]
            metrics_to_be_returned.append(self._get_mem_summary(request_time, namespace))

        if send_disk_data and (self.kb_r > 0 or self.kb_w > 0):
            namespace=[
                snap.NamespaceElement(value="hyppo"),
                snap.NamespaceElement(value="hyppo-monitor"),
                snap.NamespaceElement(value=user_id),
                snap.NamespaceElement(value=hostname),
                snap.NamespaceElement(value="container"),
                snap.NamespaceElement(value=str(self.container_id)),
                snap.NamespaceElement(value="disk_summary")
            ]
            metrics_to_be_returned.append(self._get_disk_summary(request_time, namespace))

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

        if self.mem_RSS > 0:
            fmt = '{:<20} {:<23} {:<23} {:<23}'
            output_line = output_line + "\n" + fmt.format(
                    bcolors.GREEN + "\tMemory (kB): " + bcolors.ENDC,
                    bcolors.BLUE + "RSS: " + bcolors.ENDC
                        + str(self.mem_RSS),
                    bcolors.BLUE + "PSS: " + bcolors.ENDC
                        + str(self.mem_PSS),
                    bcolors.BLUE + "USS: " + bcolors.ENDC
                        + str(self.mem_USS)
            )
        
        if (self.kb_r > 0 or self.kb_w > 0):
            fmt = '{:<20} {:<23} {:<23} {:<23} {:<23} {:23}'
            output_line = output_line + "\n" + fmt.format(
                    bcolors.GREEN + "\tDisk Stats: " + bcolors.ENDC,
                    bcolors.BLUE + "Kb R: " + bcolors.ENDC
                        + str(self.kb_r),
                    bcolors.BLUE + "Kb W: " + bcolors.ENDC
                        + str(self.kb_w),
                    bcolors.BLUE + "NUM R: " + bcolors.ENDC
                        + str(self.num_r),
                    bcolors.BLUE + "NUM W: " + bcolors.ENDC
                        + str(self.num_w),
                    bcolors.BLUE + "AVG LAT (ms): " + bcolors.ENDC
                        + str(round(self.disk_avg_lat,3))
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
