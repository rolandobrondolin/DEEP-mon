#!/usr/bin/env python

import logging
from google.protobuf import json_format
import snap_plugin.v1 as snap
import grpc
import hyppo_proto.hyppo_pb2_grpc as hyppo_remote_collector_pb2_grpc
import hyppo_proto.hyppo_pb2 as hyppo_remote_collector_pb2

LOG = logging.getLogger(__name__)


class ContainerNamerGrpcPublisher(snap.Publisher):

    def __init__(self, name, version, **kwargs):
        super(ContainerNamerGrpcPublisher, self).__init__(name, version, **kwargs)

    def generate_iterator(self, metrics):
        for _ in metrics:
            iterated_metric = hyppo_remote_collector_pb2.DataPoint(datapoint=json_format.MessageToJson(_._pb, including_default_value_fields=True))
            yield iterated_metric

    def publish(self, metrics, config):
        LOG.debug("HyppoPublisher Publish called")
        """
        Args:
            metrics (obj:`list` of :obj:`snap_plugin.v1.Metric`):
                List of metrics to be collected.
        Returns:
            :obj:`list` of :obj:`snap_plugin.v1.Metric`:
                List of collected metrics.
        """
        if len(metrics) > 0:
            channel = grpc.insecure_channel(config["remote_collector"])
            stub = hyppo_remote_collector_pb2_grpc.HyppoRemoteCollectorStub(channel)
            iterator = self.generate_iterator(metrics)
            ack = stub.SendKubeSample(iterator)


    def get_config_policy(self):
        LOG.debug("ContainerNamerGrpcPublisher GetConfigPolicy called")
        return snap.ConfigPolicy(
            [
                None,
                [
                    (
                        "remote_collector",
                        snap.StringRule(default="localhost:37000")
                    )
                ]
            ],
        )

if __name__ == "__main__":
    ContainerNamerGrpcPublisher("container-namer-grpc-publisher", 1).start_plugin()
