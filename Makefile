# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help run stop build

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help


# DOCKER TASKS
run: ## Run the monitor container
	sudo docker run -d --privileged --name hyppo_monitor -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro -v /sys/kernel/debug:/sys/kernel/debug:ro -v /proc:/host/proc:ro -v $$PWD/snap_task/distributed_w_grpc:/opt/snap/tasks:ro --net host hyppo_monitor

run-standalone: ## Run the standalone image, without snap and backend integration
	sudo docker run --rm --privileged --name hyppo_monitor_standalone -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro -v /sys/kernel/debug:/sys/kernel/debug:ro -v /proc:/host/proc:ro --net host hyppo_monitor_standalone

run-prod: ## Run the monitor container
	sudo docker run -d --privileged --name hyppo_monitor -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro -v /sys/kernel/debug:/sys/kernel/debug:ro -v /proc:/host/proc:ro --net host hyppo_monitor

stop: ## Stop the monitor container
	sudo docker stop hyppo_monitor

build: ## Build the monitor container
	sudo docker build . -t "hyppo_monitor"

build-standalone: ## Build a standalone image, without snap and backend integration
	sudo docker build . -f Dockerfile.standalone -t "hyppo_monitor_standalone"

build-kube:
	sudo docker build -t registry.gitlab.com/projecthyppo/monitor .
	sudo docker push registry.gitlab.com/projecthyppo/monitor

run-kube:
	kubectl apply -f hyppo-monitor-daemonset.yaml

stop-kube:
	kubectl delete -f hyppo-monitor-daemonset.yaml

run-kube-act:
	kubectl apply -f hyppo-monitor-act-daemonset.yaml

stop-kube-act:
	kubectl delete -f hyppo-monitor-act-daemonset.yaml
