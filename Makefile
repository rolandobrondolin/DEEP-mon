#    DEEP-mon
#    Copyright (C) 2020  Brondolin Rolando
#
#    This file is part of DEEP-mon
#
#    DEEP-mon is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    DEEP-mon is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help run stop build

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

# DOCKER TASKS
run: ## Run a standalone image with text UI
	sudo docker run -it --rm --privileged --name deep-mon -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro -v /sys/kernel/debug:/sys/kernel/debug:rw -v /proc:/host/proc:ro -v ${PWD}/config.yaml:/home/config.yaml -v /var/run/docker.sock:/var/run/docker.sock --net host deep-mon

explore: ## Run a standalone image with bash to check stuff
	sudo docker run -it --rm --privileged --name deep-mon -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro -v /sys/kernel/debug:/sys/kernel/debug:rw -v /proc:/host/proc:ro -v ${PWD}/config.yaml:/home/config.yaml -v /var/run/docker.sock:/var/run/docker.sock --net host deep-mon bash


build: ## Build a standalone image
	sudo docker build . -t "deep-mon"

build-no-cache: ## Build a standalone image without cache
	sudo docker build . -t "deep-mon" --no-cache
