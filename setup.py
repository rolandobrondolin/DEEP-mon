from setuptools import setup, find_packages

setup(
    name='hyppo-monitor',
    version='0.1dev',
    packages=['hyppo_monitor','hyppo_monitor.bpf','hyppo_monitor.rapl'],
    py_modules=['cli'],
    package_data={'hyppo_monitor.bpf': ['*.c']},
    include_package_data=True,
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        cli=hyppo_monitor.cli:deepmon
    ''',
    #license='Creative Commons Attribution-Noncommercial-Share Alike license',
    #long_description=open('README.txt').read(),
)
