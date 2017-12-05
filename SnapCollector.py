import snap_plugin.v1 as snap

class HyppoStreamCollector(snap.StreamCollector):

    def get_config_policy(self):
        LOG.debug("GetConfigPolicy called on HyppoStreamCollector")
        return snap.ConfigPolicy(
            [
                ("HyppoStreamCollector"),
                [
                    (
                        "kube_conf_path",
                        snap.StringRule(default = "", required = False)
                    )
                ]
            ]
        )

    def stream(self, metrics):
        LOG.debug("Metrics collection called on HyppoStreamCollector")



    def update_catalog(self, config):
        LOG.debug("update_catalog called on HyppoStreamCollector")
        metrics = []
        #pid related metrics
        for key in ("ID", "cycles", "instructions", "time_ns", "power", "cpu"):
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="monitor"),
                    snap.NamespaceElement(value="thread"),
                    snap.NamespaceElement.dynamic_namespace_element(name="pid")
                    snap.NamespaceElement(value=key)
                ],
                version=1,
                tags={"mtype": "gauge"},
                description="Random {}".format(key),
            )
            metrics.append(metric)
        #container related metrics
        for key in ("ID", "cycles", "instructions", "time_ns", "power", "cpu"):
            metric = snap.Metric(
                namespace=[
                    snap.NamespaceElement(value="hyppo"),
                    snap.NamespaceElement(value="monitor"),
                    snap.NamespaceElement(value="container"),
                    snap.NamespaceElement.dynamic_namespace_element(name="id")
                    snap.NamespaceElement(value=key)
                ],
                version=1,
                tags={"mtype": "gauge"},
                description="Random {}".format(key),
            )
            metrics.append(metric)

        return metrics

if __name__ == "__main__":
    HyppoStreamCollector("hyppo-monitor", 1).start_plugin()
