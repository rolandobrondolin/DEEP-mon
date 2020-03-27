from __future__ import print_function
from bcc import BPF
import ctypes as ct
import numpy as np
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from collections import namedtuple
import os
from ddsketch.ddsketch import DDSketch


from enum import Enum

HTTPSessionKey = namedtuple('HTTPSession', ['saddr', 'lport', 'daddr', 'dport', 'path'])
TCPSessionKey = namedtuple('TCPSession', ['saddr', 'lport', 'daddr', 'dport'])
TCPEndpointKey = namedtuple('TCPEndpoint', ['addr', 'port'])

def get_ipv4_endpoint_key(k):
    return TCPEndpointKey(addr=inet_ntop(AF_INET, pack("I", k.addr)),
                        port=k.port)

def get_ipv6_endpoint_key(k):
    return TCPEndpointKey(addr=inet_ntop(AF_INET6, k.addr),
                        port=k.port)

def get_ipv4_session_key(k):
    return TCPSessionKey(saddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET, pack("I", k.daddr)),
                         dport=k.dport)

def get_ipv6_session_key(k):
    return TCPSessionKey(saddr=inet_ntop(AF_INET6, k.saddr),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET6, k.daddr),
                         dport=k.dport)

def get_ipv4_http_session_key(k):
    return HTTPSessionKey(saddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET, pack("I", k.daddr)),
                         dport=k.dport,
                         path=k.http_payload)

def get_ipv6_http_session_key(k):
    return HTTPSessionKey(saddr=inet_ntop(AF_INET6, k.saddr),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET6, k.daddr),
                         dport=k.dport,
                         path=k.http_payload)

def get_session_key_by_type(k, type):
    if type is TransactionType.ipv4_tcp:
        return get_ipv4_session_key(k)
    elif type is TransactionType.ipv4_http:
        return get_ipv4_http_session_key(k)
    elif type is TransactionType.ipv6_tcp:
        return get_ipv6_session_key(k)
    elif type is TransactionType.ipv6_http:
        return get_ipv6_http_session_key(k)
    return None

class TransactionType(Enum):
    ipv4_tcp = 0
    ipv4_http = 1
    ipv6_tcp = 2
    ipv6_http = 3

class TransactionRole(Enum):
    client = -1
    server = 1

class TransactionData:

    def __init__(self, type, role, saddr, lport, daddr, dport, transaction_count, byte_rx, byte_tx):
        self.type = type
        self.role = role
        self.saddr = saddr
        self.lport = lport
        self.daddr = daddr
        self.dport = dport
        self.t_count = transaction_count
        self.byte_rx = byte_rx
        self.byte_tx = byte_tx
        self.avg = 0
        self.p50 = 0
        self.p75 = 0
        self.p90 = 0
        self.p99 = 0
        self.p99_9 = 0
        self.p99_99 = 0
        self.p99_999 = 0
        self.http_path = ""
        self.samples = []

    def load_latencies(self, latency_sketch, total_time, transaction_count):
        self.samples = latency_sketch
        self.avg = float(total_time) / float(transaction_count * 1000000)

        self.p50 = latency_sketch.quantile(0.5)
        self.p75 = latency_sketch.quantile(0.75)
        self.p90 = latency_sketch.quantile(0.9)
        self.p99 = latency_sketch.quantile(0.99)
        self.p99_9 = latency_sketch.quantile(0.999)
        self.p99_99 = latency_sketch.quantile(0.9999)
        self.p99_999 = latency_sketch.quantile(0.99999)

    def load_http_path(self, path):
        self.http_path = path

    def get_type(self):
        return self.type

    def get_type_str_no_ip(self):
        if self.type is TransactionType.ipv6_tcp or self.type is TransactionType.ipv4_tcp:
            return "tcp"
        else:
            return "http"

    def get_role(self):
        return self.role

    def get_role_str(self):
        if self.role is TransactionRole.client:
            return "client"
        else:
            return "server"

    def get_saddr(self):
        return self.saddr

    def get_lport(self):
        return self.lport

    def get_daddr(self):
        return self.daddr

    def get_dport(self):
        return self.dport

    def get_transaction_count(self):
        return self.t_count

    def get_byte_rx(self):
        return self.byte_rx

    def get_byte_tx(self):
        return self.byte_tx

    def get_avg_latency(self):
        return self.avg

    def get_percentiles(self):
        return [self.p50, self.p75, self.p90, self.p99, self.p99_9, self.p99_99, self.p99_999]

    def get_http_path(self):
        return self.http_path

    def get_samples(self):
        return self.samples

    def set_saddr(self, saddr):
        self.saddr = saddr

    def set_lport(self, lport):
        self.lport = lport

    def set_daddr(self, daddr):
        self.daddr = daddr

    def set_dport(self, dport):
        self.dport = dport


    def __str__(self):
        role_str = ""
        if self.role is TransactionRole.server:
            role_str = "server"
        else:
            role_str = "client"

        output_str = ""
        if self.type == TransactionType.ipv4_http or self.type == TransactionType.ipv6_http:
            fmt = '{:<8} {:<40} {:<40} {:<20} {:<20} {:<20} {:<25} {:<68}'
            output_str = fmt.format(
                role_str,
                "SRC: " + str(self.saddr) + ":" + str(self.lport),
                "DST: " + str(self.daddr) + ":" + str(self.dport),
                "T_COUNT: " + str(self.t_count),
                "BYTE_TX: " + str(self.byte_tx),
                "BYTE_RX: " + str(self.byte_rx),
                "LAT_AVG (ms): " + '{:.5f}'.format(self.avg),
                str(self.http_path)
            )

        else:
            fmt = '{:<8} {:<40} {:<40} {:<20} {:<20} {:<20} {:<25}'
            output_str = fmt.format(
                role_str,
                "SRC: " + str(self.saddr) + ":" + str(self.lport),
                "DST: " + str(self.daddr) + ":" + str(self.dport),
                "T_COUNT: " + str(self.t_count),
                "BYTE_TX: " + str(self.byte_tx),
                "BYTE_RX: " + str(self.byte_rx),
                "LAT_AVG (ms): " + '{:.5f}'.format(self.avg)
            )

        fmt = '{:<5} {:<30} {:<30} {:<30} {:<30} {:<30} {:<30} {:<30}'
        output_str = output_str + "\n" + fmt.format(
            "--->",
            "50p: " + '{:.5f}'.format(self.p50),
            "75p: " + '{:.5f}'.format(self.p75),
            "90p: " + '{:.5f}'.format(self.p90),
            "99p: " + '{:.5f}'.format(self.p99),
            "99.9p: " + '{:.5f}'.format(self.p99_9),
            "99.99p: " + '{:.5f}'.format(self.p99_99),
            "99.999p: " + '{:.5f}'.format(self.p99_999),
        )

        return output_str



class NatData:
    def __init__(self, type, saddr, lport, daddr, dport):
        self.type = type
        self.saddr = saddr
        self.lport = lport
        self.daddr = daddr
        self.dport = dport

    def get_type(self):
        return self.type

    def get_saddr(self):
        return self.saddr

    def get_lport(self):
        return self.lport

    def get_daddr(self):
        return self.daddr

    def get_dport(self):
        return self.dport

    def __str__(self):

        fmt = '{:<10} {:<40} {:<40}'
        output_str = fmt.format(
            "NAT RULE",
            "SRC: " + str(self.saddr) + ":" + str(self.lport),
            "DST: " + str(self.daddr) + ":" + str(self.dport),
        )

        return output_str



class NetSample:

    def __init__(self, pid_dictionary, nat_dictionary, nat_list, host_transaction_count, host_byte_tx, host_byte_rx):
        self.pid_dictionary = pid_dictionary
        self.nat_dictionary = nat_dictionary
        self.host_transaction_count = host_transaction_count
        self.host_byte_tx = host_byte_tx
        self.host_byte_rx = host_byte_rx
        self.nat_list = nat_list

    def get_pid_dictionary(self):
        return self.pid_dictionary

    def get_nat_dictionary(self):
        return self.nat_dictionary

    def get_host_transaction_count(self):
        return self.host_transaction_count

    def get_host_byte_tx(self):
        return self.host_byte_tx

    def get_host_byte_rx(self):
        return self.host_byte_rx

    def get_nat_list(self):
        return self.nat_list



class NetCollector:

    def __init__(self, trace_nat=False, dynamic_tcp_client_port_masking=False):
        self.ebpf_tcp_monitor = None
        self.nat = trace_nat
        self.dynamic_tcp_client_port_masking = dynamic_tcp_client_port_masking

        # define hash tables, skip endpoints and connections for now
        # as they self manage and self clean in eBPF code
        self.ipv4_summary = [None, None]
        self.ipv6_summary = [None, None]
        self.ipv4_http_summary = [None, None]
        self.ipv6_http_summary = [None, None]
        self.rewritten_rules = None
        self.rewritten_rules_6 = None

        self.ipv4_latency = [None, None]
        self.ipv6_latency = [None, None]
        self.ipv4_http_latency = [None, None]
        self.ipv6_http_latency = [None, None]

        self.latency_index_max = 240
        self.bucket_count = 12
        self.latency_bucket_size = 20

        self.tcp_dyn_masking_threshold = 10

    def start_capture(self):
        bpf_code_path = os.path.dirname(os.path.abspath(__file__)) \
                        + "/bpf/tcp_monitor.c"

        cflags = ["-DLATENCY_SAMPLES=%d" % self.latency_index_max, \
                    "-DLATENCY_BUCKET_SIZE=%d" % self.latency_bucket_size, \
                    "-DBUCKET_COUNT=%d" % self.bucket_count]
        if self.nat:
            cflags.append("-DBYPASS")
            cflags.append("-DREVERSE_BYPASS")
        if BPF.tracepoint_exists("sock", "inet_sock_set_state"):
            cflags.append("-DSET_STATE_4_16")
        elif BPF.tracepoint_exists("tcp", "tcp_set_state"):
            cflags.append("-DSET_STATE_4_15")
        else:
            cflags.append("-DSET_STATE_KPROBE")
        if self.dynamic_tcp_client_port_masking:
            cflags.append("-DDYN_TCP_CLIENT_PORT_MASKING")
            cflags.append("-DDYN_TCP_CLIENT_PORT_MASKING_THRESHOLD=%d" % self.tcp_dyn_masking_threshold)

        print(cflags)

        self.ebpf_tcp_monitor = BPF(src_file=bpf_code_path, cflags=cflags)

        self.ipv4_summary[0] = self.ebpf_tcp_monitor["ipv4_summary"]
        self.ipv6_summary[0] = self.ebpf_tcp_monitor["ipv6_summary"]
        self.ipv4_http_summary[0] = self.ebpf_tcp_monitor["ipv4_http_summary"]
        self.ipv6_http_summary[0] = self.ebpf_tcp_monitor["ipv6_http_summary"]
        self.ipv4_summary[1] = self.ebpf_tcp_monitor["ipv4_summary_1"]
        self.ipv6_summary[1] = self.ebpf_tcp_monitor["ipv6_summary_1"]
        self.ipv4_http_summary[1] = self.ebpf_tcp_monitor["ipv4_http_summary_1"]
        self.ipv6_http_summary[1] = self.ebpf_tcp_monitor["ipv6_http_summary_1"]
        self.rewritten_rules = self.ebpf_tcp_monitor["rewritten_rules"]
        self.rewritten_rules_6 = self.ebpf_tcp_monitor["rewritten_rules_6"]

        self.ipv4_latency[0] = self.ebpf_tcp_monitor["ipv4_latency"]
        self.ipv6_latency[0] = self.ebpf_tcp_monitor["ipv6_latency"]
        self.ipv4_http_latency[0] = self.ebpf_tcp_monitor["ipv4_http_latency"]
        self.ipv6_http_latency[0] = self.ebpf_tcp_monitor["ipv6_http_latency"]
        self.ipv4_latency[1] = self.ebpf_tcp_monitor["ipv4_latency_1"]
        self.ipv6_latency[1] = self.ebpf_tcp_monitor["ipv6_latency_1"]
        self.ipv4_http_latency[1] = self.ebpf_tcp_monitor["ipv4_http_latency_1"]
        self.ipv6_http_latency[1] = self.ebpf_tcp_monitor["ipv6_http_latency_1"]

        self.bpf_config = self.ebpf_tcp_monitor["conf"]
        self.selector = 0
        self.bpf_config[ct.c_int(0)] = ct.c_uint(self.selector)

    def get_sample(self):
        #iterate over summary tables
        pid_dict = {}
        nat_dict = {}
        nat_list = []
        host_transaction_count = 0
        host_byte_tx = 0
        host_byte_rx = 0

        bucket_count = 0

        old_selector = self.selector

        if self.selector == 0:
            self.selector = 1
        else:
            self.selector = 0
        self.bpf_config[ct.c_int(0)] = ct.c_uint(self.selector)

        # set the types and tables to iterate on
        transaction_types = [TransactionType.ipv4_tcp, TransactionType.ipv6_tcp, TransactionType.ipv4_http, TransactionType.ipv6_http]
        transaction_tables = [self.ipv4_summary[old_selector], self.ipv6_summary[old_selector], self.ipv4_http_summary[old_selector], self.ipv6_http_summary[old_selector]]
        transaction_latencies = [self.ipv4_latency[old_selector], self.ipv6_latency[old_selector], self.ipv4_http_latency[old_selector], self.ipv6_http_latency[old_selector]]

        # transaction_types = [TransactionType.ipv4_http, TransactionType.ipv6_http]
        # transaction_tables = [self.ipv4_http_summary, self.ipv6_http_summary]
        for i in range(0,len(transaction_types)):
            transaction_type = transaction_types[i]
            transaction_table = transaction_tables[i]
            transaction_latency = transaction_latencies[i]

            latency_data = {}

            # retrieve latency reservoir data
            for key, value in transaction_latency.items():
                formatted_key = get_session_key_by_type(key, transaction_type)
                sketch = latency_data[formatted_key] = latency_data.get(formatted_key, DDSketch())

                for i in range(0, self.latency_bucket_size):
                    if value.latency_vector[i] > 0:
                        sketch.add(float(value.latency_vector[i]) / 1000000)
                        bucket_count = bucket_count+1
                # if value.latency_vector[0] > 0:
                #     sketch.add(float(value.latency_vector[0]) / 1000000)
                #     bucket_count = bucket_count+1
            # print(latency_data)

            for key, value in transaction_table.items():
                data_item = None
                formatted_key = get_session_key_by_type(key, transaction_type)
                if value.status == 0 and self.nat:
                    # we found a nat rule, use the appropriate object
                    data_item = NatData(transaction_type, formatted_key.saddr, formatted_key.lport, formatted_key.daddr, formatted_key.dport)
                    nat_list.append(data_item)
                    # add the nat rule to the pid
                    if int(value.pid) in nat_dict:
                        nat_dict[int(value.pid)].append(data_item)
                    else:
                        nat_dict[int(value.pid)] = [data_item]

                else:
                    role = None
                    if int(value.status) == -1:
                        role = TransactionRole.client;
                    elif int(value.status) == 1:
                        role = TransactionRole.server;

                    data_item = TransactionData(transaction_type, role, formatted_key.saddr, formatted_key.lport, formatted_key.daddr, formatted_key.dport, int(value.transaction_count), int(value.byte_rx), int(value.byte_tx))
                    try:
                        data_item.load_latencies(latency_data[formatted_key], int(value.time), int(value.transaction_count))
                    except KeyError:
                        # skip item if we lost it somehow
                        continue

                    if transaction_type == TransactionType.ipv4_http or transaction_type == TransactionType.ipv6_http:
                        data_item.load_http_path(str(key.http_payload))

                    # sum up host metrics
                    host_transaction_count = host_transaction_count + int(value.transaction_count)
                    host_byte_tx = host_byte_tx + int(value.byte_tx)
                    host_byte_rx = host_byte_rx + int(value.byte_rx)

                    # add the data to the pid
                    if int(value.pid) in pid_dict:
                        pid_dict[int(value.pid)].append(data_item)
                    else:
                        pid_dict[int(value.pid)] = [data_item]

        #print(len(self.ipv4_summary[old_selector]))
        # print(len(self.ebpf_tcp_monitor["recv_cache"]))
        # print(len(self.ebpf_tcp_monitor["ipv4_endpoints"]))
        # print(len(self.ebpf_tcp_monitor["ipv4_connections"]))
        #print(len(self.ebpf_tcp_monitor["ipv6_connections"]))
        # print(len(self.ipv6_summary))
        # print(len(self.ipv4_http_summary))
        # print(len(self.ipv6_http_summary))
        # print(len(self.ipv4_latency[old_selector]))
        # print(len(self.ipv4_http_summary[old_selector]) + len(self.ipv4_summary[old_selector]) + len(self.ipv6_http_summary[old_selector]) + len(self.ipv6_summary[old_selector]))
        # print(len(self.ipv4_http_latency[old_selector]) + len(self.ipv4_latency[old_selector]) + len(self.ipv6_http_latency[old_selector]) + len(self.ipv6_latency[old_selector]))
        # print(bucket_count)
        try:
            # clear tables for next sample
            self.ipv4_summary[old_selector].clear()
            self.ipv6_summary[old_selector].clear()
            self.ipv4_http_summary[old_selector].clear()
            self.ipv6_http_summary[old_selector].clear()
        except Exception as e:
            print(e)
            # try to clean rewritten rules as for each packet the useful nat rules
            # are rewritten inside the tables automatically
        try:
            self.rewritten_rules.clear()
            self.rewritten_rules_6.clear()
        except Exception as e:
            print(e)

        try:
            # clear also reservoir hashmaps
            self.ipv4_latency[old_selector].clear()
            self.ipv6_latency[old_selector].clear()
            self.ipv4_http_latency[old_selector].clear()
            self.ipv6_http_latency[old_selector].clear()
        except Exception as e:
            print(e)

        return NetSample(pid_dict, nat_dict, nat_list, host_transaction_count, host_byte_tx, host_byte_rx)
