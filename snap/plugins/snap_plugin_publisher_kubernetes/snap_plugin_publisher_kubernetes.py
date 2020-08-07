#!/usr/bin/env python3

import json
import logging
import snap_plugin.v1 as snap
import os
import time
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

import urllib.request
import urllib.parse

from google.protobuf import json_format

LOG = logging.getLogger(__name__)


class KubernetesPublisher(snap.Publisher):

    def __init__(self, name, version, **kwargs):
        super(KubernetesPublisher, self).__init__(name, version, **kwargs)

        self.config = {}
        self.customer_id = ""


    def publish(self, metrics, config):
        LOG.debug("KubernetesPublisher called")
        """
        Args:
            metrics (obj:`list` of :obj:`snap_plugin.v1.Metric`):
                List of metrics to be collected.
        Returns:
            :obj:`list` of :obj:`snap_plugin.v1.Metric`:
                List of collected metrics.
        """
        if self.customer_id == "":
            #time.sleep(1)
            try:
                with open('/hyppo-config/config.yaml', 'r') as config_file:
                    self.config = yaml.load(config_file)
            except Exception:
                try:
                    with open('hyppo_monitor/config.yaml', 'r') as config_file:
                        self.config = yaml.load(config_file)
                except Exception:
                    LOG.error("Couldn't find a config file, current path is %s", os.getcwd())

            try:
                self.customer_id = self.config["customer_id"]
            except KeyError as e:
                self.customer_id = "not_registered"



        data = []
        for metric in metrics:
            data.append(json_format.MessageToDict(metric._pb, including_default_value_fields=True))

        payload = {"customer_id": self.customer_id, "data": data}

        try:
            req = urllib.request.Request("http://" + config["remote_collector"] + "/send_kube")
            req.add_header('Content-Type', 'application/json')
            json_data = json.dumps(payload)
            json_data_bytes = json_data.encode("utf-8")
            response = urllib.request.urlopen(req, json_data_bytes)
        except Exception:
            import traceback
            LOG.error(traceback.format_exc())

    def get_config_policy(self):
        LOG.debug("KubernetesPublisher GetConfigPolicy called")
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
    KubernetesPublisher("kubernetes-publisher", 1).start_plugin()
