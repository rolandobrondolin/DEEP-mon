#!/usr/bin/env python

import json
import logging
import snap_plugin.v1 as snap
import urllib2

from google.protobuf import json_format

LOG = logging.getLogger(__name__)


class HyppoPublisher(snap.Publisher):

    def __init__(self, name, version, **kwargs):
        self.connected = False
        super(HyppoPublisher, self).__init__(name, version, **kwargs)

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

        data = []
        for metric in metrics:
            data.append(json_format.MessageToDict(metric._pb, including_default_value_fields=True))

        try:
            req = urllib2.Request("http://" + config["remote_collector"] + "/send_data")
            req.add_header('Content-Type', 'application/json')
            response = urllib2.urlopen(req, json.dumps(data))
        except Exception:
            import traceback
            LOG.error(traceback.format_exc())


    def get_config_policy(self):
        LOG.debug("HyppoPublisher GetConfigPolicy called")
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
    HyppoPublisher("hyppo-publisher", 1).start_plugin()
