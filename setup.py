from setuptools import setup, find_packages

setup(
    name='hyppo-monitor',
    version='0.1dev',
    packages=find_packages(),
    package_data={'hyppo_monitor.bpf': ['*.c']},
    include_package_data=True
    #license='Creative Commons Attribution-Noncommercial-Share Alike license',
    #long_description=open('README.txt').read(),
)
