#!/usr/bin/env python

import json
import logging
import snap_plugin.v1 as snap
import urllib2

from google.protobuf import json_format

LOG = logging.getLogger(__name__)


class KubernetesPublisher(snap.Publisher):

    def __init__(self, name, version, **kwargs):
        super(KubernetesPublisher, self).__init__(name, version, **kwargs)
        self.connected = False

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

        data = []
        for metric in metrics:
            data.append(json_format.MessageToDict(metric._pb, including_default_value_fields=True))

        try:
            req = urllib2.Request("http://" + config["remote_collector"] + "/send_kube")
            req.add_header('Content-Type', 'application/json')
            response = urllib2.urlopen(req, json.dumps(data))
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
