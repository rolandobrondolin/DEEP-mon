FROM ubuntu:18.04
LABEL maintainer="Rolando Brondolin"

RUN apt-get clean && apt-get update && apt-get install -y python3 python3-pip locales locales-all libelf1
RUN pip3 install numpy


#Needed by Curse to print unicode characters to the terminal
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

#install bcc, our mod of kubernetes client, and ddsketch

RUN buildDeps='python python-pip wget curl apt-transport-https git bison build-essential cmake flex libedit-dev libllvm6.0 llvm-6.0-dev libclang-6.0-dev zlib1g-dev libelf-dev' \
  && apt-get update && apt-get install -y $buildDeps \
  && git clone https://github.com/iovisor/bcc.git \
  && mkdir bcc/build \
  && cd bcc/build \
  && cmake .. \
  && make \
  && make install \
  && cmake -DPYTHON_CMD=python3 .. \
  && cd src/python/ \
  && make \
  && make install \
  && cd / \
  && rm -r bcc \
  && git clone --recursive https://gitlab.com/projecthyppo/kubernetes-client-python.git \
  && cd kubernetes-client-python \
  && pip3 install . \
  && cd / \
  && rm -r kubernetes-client-python \
  && git clone https://github.com/DataDog/sketches-py.git \
  && cd sketches-py \
  && python3 setup.py install \
  && cd / \
  && rm -r sketches-py \
  && apt-get purge -y --auto-remove $buildDeps

WORKDIR /home

RUN mkdir /home/deep_mon
ADD bpf /home/deep_mon/bpf
ADD userspace /home/deep_mon/userspace
ADD deep_mon.py /home/deep_mon/
ADD setup.py /home

#Install plugin dependencies
RUN pip3 install . && rm -rf /home/deep_mon && rm setup.py

# "-u" forces the binary I/O layers of stdout and stderr to be unbuffered and
# is needed to avoid truncated output in Docker
ENV PYTHONUNBUFFERED="on"
CMD ["deep-mon"]
