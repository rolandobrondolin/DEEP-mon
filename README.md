# DEEP-mon (Hyppo monitor)


## Standalone local deployment (Textual output)
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

## Kubernetes deployment (Integrated with Grafana)
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

#### Build DEEP-mon
To run DEEP-mon on Kubernetes use the command
```
make run-kube
```
that loads the DaemonSet from `hyppo-monitor-daemonset.yaml` running a monitor container on each Node.
If there is already a DaemonSet running you will see the message `daemonset "hyppo-monitor" unchanged`.
In that case delete the DaemonSet with `make stop-kube` before starting it.


## Troubleshooting
#### Kubernetes is not able to download the images
If kubernetes is not able to download the images:
1. Create a secret in kubernetes (if not there yet) with access tokens for the remote container registry
```
kubectl create secret -n "kube-system" docker-registry gitlab-registry --docker-server="https://registry.gitlab.com" --docker-username="GITLAB USERNAME HERE" --docker-password="GITLAB PASSWORD HERE" --docker-email="GITLAB EMAIL HERE" -o yaml --dry-run | sed 's/dockercfg/dockerconfigjson/g' | kubectl replace -n "kube-system" --force -f -
```
2. [Relaunch](#build-deep-mon-1) the monitor DaemonSet

## Old stuff
To make available data from k8s inside the pod, tweak with RBAC:
- `kubectl create clusterrolebinding --user system:serviceaccount:kube-system:default kube-system-cluster-admin --clusterrole cluster-admin`

