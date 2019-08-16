from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, strftime
from subprocess import call
from collections import namedtuple, defaultdict


TCPSessionKey = namedtuple('TCPSession', ['laddr', 'lport', 'daddr', 'dport'])
TCPEndpointKey = namedtuple('TCPEndpoint', ['addr', 'port'])

def get_ipv4_endpoint_key(k):
    return TCPEndpointKey(addr=inet_ntop(AF_INET, pack("I", k.addr)),
                        port=k.port)

def get_ipv6_endpoint_key(k):
    return TCPEndpointKey(addr=inet_ntop(AF_INET6, k.addr),
                        port=k.port)

def get_ipv4_session_key(k):
    return TCPSessionKey(laddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET, pack("I", k.daddr)),
                         dport=k.dport)

def get_ipv6_session_key(k):
    return TCPSessionKey(laddr=inet_ntop(AF_INET6, k.saddr),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET6, k.daddr),
                         dport=k.dport)

ebpf_tcp_monitor = BPF(src_file="tcp_monitor.c")

ipv4_endpoints = ebpf_tcp_monitor["ipv4_endpoints"]
ipv6_endpoints = ebpf_tcp_monitor["ipv6_endpoints"]
ipv4_connections = ebpf_tcp_monitor["ipv4_connections"]
ipv6_connections = ebpf_tcp_monitor["ipv6_connections"]
ipv4_summary = ebpf_tcp_monitor["ipv4_summary"]
ipv6_summary = ebpf_tcp_monitor["ipv6_summary"]

i = 0
exiting = False
while not exiting:
    try:
        sleep(1)
    except KeyboardInterrupt:
        exiting = True

    call("clear")

    # print endpoints
    for k, v in ipv4_endpoints.items():
        key = get_ipv4_endpoint_key(k)
        print(str(key) + "   " + str(v.status) + "    " + str(v.n_connections))
    print()
    for k, v in ipv4_connections.items():
        key = get_ipv4_session_key(k)
        print(str(key) + "   " + str(v.transaction_state) + "  " + str(v.transaction_flow) + " " + str(v.byte_tx) + " " + str(v.byte_rx) \
            + " " + str(v.first_ts_in) + " " + str(v.last_ts_in) + " " + str(v.first_ts_out) + " " + str(v.last_ts_out))
    for k, v in ipv4_summary.items():
        key = get_ipv4_session_key(k)
        status = "unknown"
        if v.status == 1:
            status = "server"
        elif v.status == -1:
            status = "client"
        print(status + "   " + str(key) + "   " + str(v.transaction_count) + "  " + str(v.byte_tx) + " " + str(v.byte_rx))
        print(str(list(v.latency)))
    print()

    for k, v in ipv6_endpoints.items():
        key = get_ipv6_endpoint_key(k)
        print(str(key) + "   " + str(v.status) + "    " + str(v.n_connections))
    print()
    for k, v in ipv6_connections.items():
        key = get_ipv6_session_key(k)
        print(str(key) + "   " + str(v.transaction_state) + "  " + str(v.transaction_flow) + " " + str(v.byte_tx) + " " + str(v.byte_rx) \
            + " " + str(v.first_ts_in) + " " + str(v.last_ts_in) + " " + str(v.first_ts_out) + " " + str(v.last_ts_out))
    for k, v in ipv6_summary.items():
        key = get_ipv6_session_key(k)
        status = "unknown"
        if v.status == 1:
            status = "server"
        elif v.status == -1:
            status = "client"
        print(status + "   " + str(key) + "   " + str(v.transaction_count) + "  " + str(v.byte_tx) + " " + str(v.byte_rx))
        print(str(list(v.latency)))
    print()

    # # IPv4: build dict of all seen keys
    # ipv4_throughput = defaultdict(lambda: [0, 0])
    # for k, v in ipv4_send_bytes.items():
    #     key = get_ipv4_session_key(k)
    #     ipv4_throughput[key][0] = v.value
    # ipv4_send_bytes.clear()
    #
    # for k, v in ipv4_recv_bytes.items():
    #     key = get_ipv4_session_key(k)
    #     ipv4_throughput[key][1] = v.value
    # ipv4_recv_bytes.clear()
    #
    # if ipv4_throughput:
    #     print("%-6s %-12s %-21s %-21s %6s %6s" % ("PID", "COMM",
    #         "LADDR", "RADDR", "RX_KB", "TX_KB"))
    #
    # # output
    # for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
    #                                           key=lambda kv: sum(kv[1]),
    #                                           reverse=True):
    #     print("%-6d %-12.12s %-21s %-21s %6d %6d" % (k.pid,
    #         pid_to_comm(k.pid),
    #         k.laddr + ":" + str(k.lport),
    #         k.daddr + ":" + str(k.dport),
    #         int(recv_bytes), int(send_bytes)))
