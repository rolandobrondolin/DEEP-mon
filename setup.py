from setuptools import setup, find_packages

setup(
    name='hyppo-monitor',
    version='0.1dev',
    packages=['hyppo_monitor','hyppo_monitor.bpf','hyppo_monitor.k8s_client','hyppo_monitor.rapl'],
    py_modules=['monitor_main'],
    package_data={'hyppo_monitor.bpf': ['*.c']},
    include_package_data=True,
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        monitor_main=hyppo_monitor.monitor_main:deepmon
    ''',
    #license='Creative Commons Attribution-Noncommercial-Share Alike license',
    #long_description=open('README.txt').read(),
)
