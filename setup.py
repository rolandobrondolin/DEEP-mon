from setuptools import setup, find_packages

setup(
    name='deep-mon',
    version='0.1dev',
    packages=['deep_mon', 'deep_mon.bpf','deep_mon.userspace','deep_mon.userspace.rapl'],
    package_data={'deep_mon.bpf': ['*.c'], 'deep_mon.userspace': ['*.yaml']},
    include_package_data=True,
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        deep-mon=deep_mon.deep_mon:main
    ''',
)
