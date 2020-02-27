# DEEP-mon (Hyppo monitor)

## Deployment

### Standalone local deployment (Textual output)
If you just want to try DEEP-mon locally, with few containers and a textual output in console, follow these steps.
If you are looking for the Kubernetes deployment with Intel Snap, Grafana Integration and additional
information about Kubernetes (pods, namespaces, etc.), look at [Kubernetes deployment](#kubernetes-deployment-integrated-with-grafana)

#### Build DEEP-mon
```
make build-standalone
```

#### Run DEEP-mon
```
make run-standalone
```

### Kubernetes deployment (Integrated with Grafana)
Deployment on Kubernetes is a little bit more involved. Containers images must be pulled
from a registry in order to run on Kubernetes, we use the Gitlab Registry for that

#### Build DEEP-mon
```
make build-kube
```
This command is composed by three operations:
1. Login to GitLab registry service
2. Build the image locally
3. Push the image to the registry

At the end of this process you can check that the image was created successfully
going to [Registry Tab](https://gitlab.com/projecthyppo/monitor/container_registry) of the project.
You should find at least an image named `projecthyppo/monitor` and check that a tag `latest`
has been created by clicking on the image name. Sometimes it might happen that during the push of
the images the image is created but not the tag, leading to issues when you try to pull the image.

#### Run DEEP-mon
To run DEEP-mon on Kubernetes use the command
```
make run-kube
```
that loads the DaemonSet from `hyppo-monitor-daemonset.yaml` running a monitor container on each Node.
If there is already a DaemonSet running you will see the message `daemonset "hyppo-monitor" unchanged`.
In that case delete the DaemonSet with `make stop-kube` before starting it.

## Configuration
There are three parameters that can be configured in DEEP-mon:
1. `kube-config`: specify the path of Kubernetes configuration file
2. `window-mode`: select between `fixed` window (information is collected from eBPF
at fixed time intervals) and `dynamic` (window length is automatically adjusted
based on average tasks duration)
3. `output-format`: select between `json`, `console` (pretty printed on terminal)
or `snap` (for Snap deployments)

Parameters can be set in two different ways. In both deployment modes you can
use the file `hyppo_monitor/config.yaml` to set them. If you are doing a
standalone deployment you can pass the parameters as flags to `cli.py`. Parameters
that are not passed as flags will get their default value from the config file.
Have a look to `CMD` in `Dockerfile.standalone` for an example. Run `cli.py -h` to
get a list of all flags.

## Troubleshooting
#### Kubernetes is not able to download the images
If kubernetes is not able to download the images:
1. Create a secret in kubernetes (if not there yet) with access tokens for the remote container registry
```
kubectl create secret -n "kube-system" docker-registry gitlab-registry --docker-server="https://registry.gitlab.com" --docker-username="GITLAB USERNAME HERE" --docker-password="GITLAB PASSWORD HERE" --docker-email="GITLAB EMAIL HERE" -o yaml --dry-run | sed 's/dockercfg/dockerconfigjson/g' | kubectl replace -n "kube-system" --force -f -
```

If you are on k8s > 1.16 use this to create the secret
```
kubectl create secret docker-registry gitlab-registry -n kube-system --docker-server=https://registry.gitlab.com --docker-username="GITLAB USERNAME HERE" --docker-password="GITLAB PASSWORD HERE" --docker-email="GITLAB EMAIL HERE"
```
2. [Relaunch](#build-deep-mon-1) the monitor DaemonSet

#### DEEP-mon is not able to extract information on Kubernetes
To make data from Kubernates available inside the pod (Pod Name, Node, Namespace, etc.), it might be necessary to tweak RBAC rules:
- `kubectl create clusterrolebinding --user system:serviceaccount:kube-system:default kube-system-cluster-admin --clusterrole cluster-admin`
