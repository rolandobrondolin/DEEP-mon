#hyppo_monitor

## Build hyppo monitor
- `make build` to build the container locally
- `make run` to run the container locally with external files
- `make build-kube` to build the container and to send it to the remote registry

## Deploy with kubernetes
- `make run-kube` to launch the monitor pod on each machine of the kubernetes cluster

## Remove containers with kubernetes
- `make stop-kube` to remove the daemonset

## Troubleshooting
If kubernetes is not able to download the images:
- create a secret in kubernetes (if not there yet) with access tokens for the remote container registry `kubectl create secret -n "kube-system" docker-registry gitlab-registry --docker-server="https://registry.gitlab.com" --docker-username="GITLAB USERNAME HERE" --docker-password="GITLAB PASSWORD HERE" --docker-email="GITLAB EMAIL HERE" -o yaml --dry-run | sed 's/dockercfg/dockerconfigjson/g' | kubectl replace -n "kube-system" --force -f -`
- try to relaunch the monitor daemonset

To make available data from k8s inside the pod, tweak with RBAC:
- `kubectl create clusterrolebinding --user system:serviceaccount:kube-system:default kube-system-cluster-admin --clusterrole cluster-admin`

## Old stuff:

### dependencies (old)
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

### Running hyppo monitor (old)
run single node deployment (deprecated):
- docker-compose build
- docker-compose up -d

run single container with distributed monitoring infrastructure:
- make build
- make run-prod

push on container registry (private)
- sudo docker login registry.gitlab.com (provide username and password)
- `make build-kube` to build the container and push it to remote registry

to run with k8s daemonset:
- `make run-kube` to apply the DaemonSet
- `make stop-kube` to remove the DaemonSet
