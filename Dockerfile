FROM ubuntu:16.04
MAINTAINER Rolando Brondolin

RUN apt-get clean
RUN apt-get update
RUN apt-get install -y python python-pip wget curl apt-transport-https git make

RUN wget https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz
RUN tar -xvf go1.13.3.linux-amd64.tar.gz
RUN mv go /usr/local

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
RUN echo "deb https://repo.iovisor.org/apt/xenial xenial main" | tee /etc/apt/sources.list.d/iovisor.list
RUN apt-get update

RUN apt-get install -y libelf1 bcc-tools libbcc-examples
ENV GOPATH /go
ENV PATH /go/bin:/usr/local/go/bin:$PATH

RUN go get -d github.com/intelsdi-x/snap && cd $GOPATH/src/github.com/intelsdi-x/snap && make && make install
RUN mkdir /opt/snap && mkdir /opt/snap/plugins && mkdir /opt/snap/tasks


# Install our mod of kubernetes client
RUN git clone --recursive https://gitlab.com/projecthyppo/kubernetes-client-python.git
RUN cd kubernetes-client-python && pip install . && cd ../ && rm -r kubernetes-client-python
RUN pip install snap-plugin-lib-py numpy==1.16

RUN git clone https://github.com/DataDog/sketches-py.git
RUN cd sketches-py && python setup.py install

WORKDIR /home

#RUN curl -sL https://github.com/grafana/snap-plugin-collector-kubestate/releases/download/1/snap-plugin-collector-kubestate_linux_x86_64 \
#    -o /opt/snap/plugins/snap-plugin-collector-kubestate_linux_x86_64

ADD hyppo_monitor /home/hyppo_monitor
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
RUN cp snap/plugins/snap_plugin_publisher_kubernetes/snap_plugin_publisher_kubernetes.py /opt/snap/plugins

RUN cp snap_task/distributed_w_http/hyppo-container-namer-http.json /opt/snap/tasks
#RUN cp snap_task/distributed_w_http/hyppo-kubestate-http.json /opt/snap/tasks
RUN cp snap_task/distributed_w_http/hyppo-monitor-http.json /opt/snap/tasks

RUN chmod 777 /opt/snap/plugins/*

CMD ["snapteld", "--log-level", "2", "--plugin-trust", "0", "--config", "/home/snapteld.conf"]
