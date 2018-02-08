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
- docker-compose build
- docker-compose up -d

run container with distributed monitoring infrastructure:
- make build
- make run-prod

push on container registry (public)
- sudo docker build -t registry.gitlab.com/projecthyppo/hyppo-public/monitor .
- sudo docker push registry.gitlab.com/projecthyppo/hyppo-public/monitor

run with k8s daemonset:
kubectl apply -f hyppo-monitor-daemonset.yaml

to make available data from k8s inside the pod, tweak with RBAC:
- kubectl create clusterrolebinding --user system:serviceaccount:kube-system:default kube-system-cluster-admin --clusterrole cluster-admin
