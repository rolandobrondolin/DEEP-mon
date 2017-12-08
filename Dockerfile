FROM ubuntu:16.04
MAINTAINER Rolando Brondolin

RUN apt-get clean
RUN apt-get update --fix-missing
RUN apt-get install -y python python-pip wget curl apt-transport-https

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
RUN echo "deb https://repo.iovisor.org/apt/xenial xenial main" | tee /etc/apt/sources.list.d/iovisor.list
RUN curl -s https://packagecloud.io/install/repositories/intelsdi-x/snap/script.deb.sh | bash
RUN apt-get update

RUN apt-get install -y libelf1 bcc-tools libbcc-examples linux-headers-$(uname -r)
RUN apt-get install -y snap-telemetry

RUN pip install kubernetes snap-plugin-lib-py

WORKDIR /home

RUN wget https://github.com/intelsdi-x/snap-plugin-publisher-influxdb/releases/download/25/snap-plugin-publisher-influxdb_linux_x86_64
RUN mv snap-plugin-publisher-influxdb_linux_x86_64 /opt/snap/plugins

ADD . /home/
RUN pip install .

RUN cp snap_collector.py /opt/snap/plugins
RUN cp snap_config/hyppo-monitor-influxdb.json /opt/snap/tasks
RUN chmod 777 /opt/snap/plugins/*

CMD ["snapteld", " --log-level 1 --log-path '' --plugin-trust 0"]
