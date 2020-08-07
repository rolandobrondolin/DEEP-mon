FROM hyppo_monitor_standalone:latest
LABEL maintainer="Rolando Brondolin"


RUN buildDeps='wget curl apt-transport-https' \
  && apt-get clean && apt-get update && apt-get install -y $buildDeps \
  && wget https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz \
  && tar -xvf go1.13.3.linux-amd64.tar.gz \
  && mv go /usr/local \
  && rm go1.13.3.linux-amd64.tar.gz \
  && apt-get purge -y --auto-remove $buildDeps

ENV GOPATH /go
ENV PATH /go/bin:/usr/local/go/bin:$PATH

RUN buildDeps='git make' \
  && apt-get clean && apt-get update && apt-get install -y $buildDeps \
  && go get -d github.com/intelsdi-x/snap \
  && cd $GOPATH/src/github.com/intelsdi-x/snap \
  && make \
  && make install \
  && rm -r $GOPATH/src/github.com/intelsdi-x/snap \
  && apt-get purge -y --auto-remove $buildDeps

# trick snapteld into using python 3 instead of python 2
RUN ln -s /usr/bin/python3 /usr/bin/python


RUN mkdir /opt/snap && mkdir /opt/snap/plugins && mkdir /opt/snap/tasks

WORKDIR /home

ADD snapteld.conf /home


#Copy plugins and tasks
COPY snap/plugins/hyppo_monitor_plugin/hyppo_monitor_plugin.py /opt/snap/plugins
COPY snap/plugins/hyppo_publisher_plugin/hyppo_publisher_plugin.py /opt/snap/plugins
COPY snap/plugins/snap_plugin_collector_container_namer/snap_plugin_collector_container_namer.py /opt/snap/plugins
COPY snap/plugins/snap_plugin_publisher_kubernetes/snap_plugin_publisher_kubernetes.py /opt/snap/plugins

COPY snap_task/distributed_w_http/hyppo-container-namer-http.json /opt/snap/tasks
COPY snap_task/distributed_w_http/hyppo-monitor-http.json /opt/snap/tasks

RUN chmod 777 /opt/snap/plugins/*

CMD ["snapteld", "--log-level", "2", "--plugin-trust", "0", "--config", "/home/snapteld.conf"]
