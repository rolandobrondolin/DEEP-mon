# dockercap_monitor

## dependencies
linux image extras

- sudo apt-get install linux-image-extra-$(uname -r) linux-image-extra-virtual

kubernetes client

- pip install kubernetes

bcc (manual install for ubuntu 16.04 for now)

- https://github.com/iovisor/bcc/blob/master/INSTALL.md

intel snap

- https://github.com/intelsdi-x/snap

intel snap plugin library python

- https://github.com/intelsdi-x/snap-plugin-lib-py (pip install . in the repository directory)
- https://github.com/intelsdi-x/snap/blob/master/docs/PLUGIN_AUTHORING.md#plugin-library

run single node deployment:
- docker-compuse build
- docker-compuse up -d

run container alone (distributed influx):

- docker build . -t "dockercap_monitor"
- docker run -d --privileged -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro -v /sys/kernel/debug:/sys/kernel/debug:ro -v /proc:/host/proc:ro -v PATH_TO_REPO/snap_task/distributed_w_influx:/opt/snap/tasks:ro --net host dockercap_monitor

run container with distributed monitoring infrastructure:

- docker build . -t "dockercap_monitor"
- docker run -d --privileged -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro -v /sys/kernel/debug:/sys/kernel/debug:ro -v /proc:/host/proc:ro -v PATH_TO_REPO/snap_task/distributed_w_grpc:/opt/snap/tasks:ro --net host dockercap_monitor
