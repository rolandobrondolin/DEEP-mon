FROM ubuntu:16.04
MAINTAINER Rolando Brondolin

RUN apt-get clean
RUN apt-get update --fix-missing
RUN apt-get install -y python python-pip wget curl apt-transport-https

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
RUN echo "deb https://repo.iovisor.org/apt/xenial xenial main" | tee /etc/apt/sources.list.d/iovisor.list
RUN curl -s https://packagecloud.io/install/repositories/intelsdi-x/snap/script.deb.sh | bash
RUN apt-get update

RUN apt-get install -y libelf1 bcc-tools libbcc-examples
RUN apt-get install -y snap-telemetry

RUN pip install kubernetes snap-plugin-lib-py

WORKDIR /home

RUN wget https://github.com/intelsdi-x/snap-plugin-publisher-influxdb/releases/download/25/snap-plugin-publisher-influxdb_linux_x86_64
RUN mv snap-plugin-publisher-influxdb_linux_x86_64 /opt/snap/plugins

ADD hyppo_monitor /home/hyppo_monitor
ADD hyppo_monitor_plugin /home/hyppo_monitor_plugin
ADD hyppo_publisher_plugin /home/hyppo_publisher_plugin
ADD snap_task /home/snap_task
ADD setup.py /home
ADD snapteld.conf /home
RUN pip install . && cd hyppo_publisher_plugin && pip install . && cd ../

RUN cp hyppo_monitor_plugin/hyppo_monitor_plugin.py /opt/snap/plugins
RUN cp -r hyppo_publisher_plugin/hyppo_publisher_plugin.py /opt/snap/plugins
RUN chmod 777 /opt/snap/plugins/*

CMD ["snapteld", "--log-level", "1", "--plugin-trust", "0", "--config", "/home/snapteld.conf"]
