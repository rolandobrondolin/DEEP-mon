FROM ubuntu:16.04
MAINTAINER Rolando Brondolin

RUN apt-get clean
RUN apt-get update
RUN apt-get install -y python python-pip wget curl apt-transport-https git

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
RUN echo "deb https://repo.iovisor.org/apt/xenial xenial main" | tee /etc/apt/sources.list.d/iovisor.list
RUN curl -s https://packagecloud.io/install/repositories/intelsdi-x/snap/script.deb.sh | bash
RUN apt-get update

RUN apt-get install -y libelf1 bcc-tools libbcc-examples
RUN apt-get install -y snap-telemetry

# Install our mod of kubernetes client
RUN git clone --recursive https://gitlab.com/projecthyppo/kubernetes-client-python.git
RUN cd kubernetes-client-python && pip install . && cd ../ && rm -r kubernetes-client-python
RUN pip install snap-plugin-lib-py

WORKDIR /home

RUN wget https://github.com/intelsdi-x/snap-plugin-publisher-influxdb/releases/download/25/snap-plugin-publisher-influxdb_linux_x86_64
RUN mv snap-plugin-publisher-influxdb_linux_x86_64 /opt/snap/plugins
RUN curl -sL https://github.com/grafana/snap-plugin-collector-kubestate/releases/download/1/snap-plugin-collector-kubestate_linux_x86_64 \
    -o /opt/snap/plugins/snap-plugin-collector-kubestate_linux_x86_64

ADD hyppo_monitor /home/hyppo_monitor
ADD hyppo_proto /home/hyppo_proto
ADD snap /home/snap
ADD snap_task /home/snap_task
ADD setup.py /home
ADD snapteld.conf /home

#Install plugin dependencies
RUN pip install .

#Copy plugins and tasks
RUN cp snap/plugins/hyppo_monitor_plugin/hyppo_monitor_plugin.py /opt/snap/plugins
RUN cp snap/plugins/hyppo_publisher_plugin/hyppo_publisher_plugin.py /opt/snap/plugins
RUN cp snap/plugins/snap_plugin_collector_container_namer/snap_plugin_collector_container_namer.py /opt/snap/plugins
RUN cp snap/plugins/snap_plugin_publisher_container_namer_grpc/snap_plugin_publisher_container_namer_grpc.py /opt/snap/plugins
RUN cp snap_task/distributed_w_grpc/hyppo-container-namer-grpc.json /opt/snap/tasks
RUN cp snap_task/distributed_w_grpc/hyppo-kubestate-grpc.json /opt/snap/tasks
RUN cp snap_task/distributed_w_grpc/hyppo-monitor-grpc.json /opt/snap/tasks

RUN chmod 777 /opt/snap/plugins/*

CMD ["snapteld", "--log-level", "1", "--plugin-trust", "0", "--config", "/home/snapteld.conf"]
