# DEEP-mon

Dynamic and Energy Efficient Power monitor (DEEP-mon) is an eBPF based monitoring tool to measure power consumption and performance of Docker containers. DEEP-mon started in 2017 as a research project of [NECSTLab](https://necst.it) at Politecnico di Milano with the goal of being able to measure the power consumption of each container running in a given host. The project then expanded and now DEEP-mon is able to measure power consumtion, performance counters, CPU usage, Memory usage, Network I/O, and File I/O, all displayed in a nice curses UI terminal window.

## Getting started

### Requirements

DEEP-mon currently runs on Docker and it is almost self contained. Requirements are:

- Linux kernel >= 4.13
- kernel headers
- make
- docker
- intel_rapl module (for power consumption stuff)

### Build and Run

To build the container, within the root folder of the project type:

```bash
make build
```

To run the container, within the root folder of the project type:

```bash
make run
```

## Bug reports

For bug reports, documentation typos or feature requests feel free to create an [issue](https://github.com/necst/DEEP-mon/issues).  
Please make sure that the same problem wasn't reported already.

## Documentation

A clear documentation is currently work in progress. If you want to contribute, feel free to create a pull request or open an issue.

## Contributing

Contribution is welcome!

* Create a pull request containing bug fixes or new features.
* [Propose](https://github.com/necst/DEEP-mon/issues/new) new functions, improvements, better documentation

## DEEP-mon roadmap:
* fix performance issue with memory metrics
* experimental measurement tool -> record stuff, single machine + distributed
* frequency sampling
* improve parameter injection
* set attribution ratio in config
* improve curse UI
* documentation (code + md files)
* tests
* add docker image, docker name in curse UI (e.g. readable docker data)
* add k8s pod name, deployments, services (e.g. readable k8s data)
* one UI per cluster (daemonset), server w/data, cli
* web UI

## Research

As we said at the beginning, this work comes form the research conducted at [NECSTLab](https://necst.it). If you use this tool for your research, please cite the following papers:

* Brondolin, Rolando, Tommaso Sardelli, and Marco D. Santambrogio. "Deep-mon: Dynamic and energy efficient power monitoring for container-based infrastructures." 2018 IEEE International Parallel and Distributed Processing Symposium Workshops (IPDPSW). IEEE, 2018. (download [here](https://ieeexplore.ieee.org/abstract/document/8425477))

* Brondolin, Rolando, and Marco D. Santambrogio. "A black-box monitoring approach to measure microservices run-time performance." ACM Transactions on Architecture and Code Optimization (TACO). (Accepted to appear, paper will be available soon)
