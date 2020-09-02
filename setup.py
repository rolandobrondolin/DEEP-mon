from setuptools import setup, find_packages

setup(
    name='deep-mon',
    version='0.1dev',
    packages=['bpf','userspace','userspace.rapl'],
    py_modules=['deep-mon'],
    package_data={'bpf': ['*.c']},
    include_package_data=True,
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        deep-mon=userspace.deep_mon:main
    ''',
    #license='Creative Commons Attribution-Noncommercial-Share Alike license',
    #long_description=open('README.txt').read(),
)
