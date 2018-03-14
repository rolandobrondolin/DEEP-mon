from setuptools import setup, find_packages

setup(
    name='hyppo-monitor',
    version='0.1dev',
    packages=['hyppo_monitor','hyppo_monitor.bpf','hyppo_monitor.k8s_client','hyppo_monitor.rapl'],
    package_data={'hyppo_monitor.bpf': ['*.c']},
    include_package_data=True
    #license='Creative Commons Attribution-Noncommercial-Share Alike license',
    #long_description=open('README.txt').read(),
)

setup(
    name='hyppo-proto',
    version='0.1dev',
    packages=['hyppo_proto'],
    #license='Creative Commons Attribution-Noncommercial-Share Alike license',
    #long_description=open('README.txt').read(),
)
