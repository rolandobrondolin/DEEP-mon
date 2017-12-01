from __future__ import division, print_function
from datetime import datetime


class RaplReader():

    def _read_sysfs_file(self, path):
        try:
            with open(path, "r") as f:
                contents = f.read().strip()
                return contents
        except EnvironmentError:
            return "0"

    def read_energy_core_sample(self, package="0"):
        energy = int(self._read_sysfs_file("/sys/class/powercap/intel-rapl/" +
            "intel-rapl:{}/intel-rapl:{}:0/energy_uj".format(package, package)))
        return RaplSample(energy, datetime.now())

    def read_energy_dram_sample(self, package="0"):
        energy = int(self._read_sysfs_file("/sys/class/powercap/intel-rapl/" +
            "intel-rapl:{}/intel-rapl:{}:1/energy_uj".format(package, package)))
        return RaplSample(energy, datetime.now())

    def read_energy_package_sample(self, package="0"):
        energy = int(self._read_sysfs_file("/sys/class/powercap/intel-rapl/" +
            "intel-rapl:{}/energy_uj".format(package)))
        return RaplSample(energy, datetime.now())


class RaplSample():
    def __init__(self, energy, timestamp):
        self.energy_uj = energy
        self.sample_time = timestamp

    def __sub__(self, other):
        energy_diff = self.energy_uj - other.energy_uj
        delta_time = (self.sample_time - other.sample_time).total_seconds()
        # this is overflow!
        if energy_diff < 0 and delta_time > 0:
            energy_diff = 2**32 + self.energy_uj - other.energy_uj
        return RaplDiff(energy_diff, delta_time)

    def energy(self):
        return self.energy_uj

    def time(self):
        return self.sample_time


class RaplDiff():
    def __init__(self, energy, time):
        self.energy_uj = energy
        self.delta_time = time

    def energy(self):
        return self.energy_uj

    def power(self):
        # Convert from microJ to J and return power consumption in delta time
        return (self.energy_uj / 1000000) / self.delta_time


class RaplMonitor():

    def __init__(self, topology):
        self.rapl_reader = RaplReader()
        self.topology = topology
        self.rapl_package_sample = [
                self.rapl_reader.read_energy_package_sample(str(skt))
                for skt in self.topology.get_sockets()]
        self.rapl_core_sample = [
                self.rapl_reader.read_energy_core_sample(str(skt))
                for skt in self.topology.get_sockets()]
        self.rapl_dram_sample = [
                self.rapl_reader.read_energy_dram_sample(str(skt))
                for skt in self.topology.get_sockets()]

    def get_package_sample(self):
        new_rapl_package_sample = [
                self.rapl_reader.read_energy_package_sample(str(skt))
                for skt in self.topology.get_sockets()]
        rapl_diff = [
                new_rapl_package_sample[skt] - self.rapl_package_sample[skt]
                for skt in self.topology.get_sockets()]
        self.rapl_package_sample = new_rapl_package_sample
        return rapl_diff

    def get_core_sample(self):
        new_rapl_core_sample = [
                self.rapl_reader.read_energy_core_sample(str(skt))
                for skt in self.topology.get_sockets()]
        rapl_diff = [new_rapl_core_sample[skt] - self.rapl_core_sample[skt]
                     for skt in self.topology.get_sockets()]
        self.rapl_core_sample = new_rapl_core_sample
        return rapl_diff

    def get_dram_sample(self):
        new_rapl_dram_sample = [
                self.rapl_reader.read_energy_dram_sample(str(skt))
                for skt in self.topology.get_sockets()]
        rapl_diff = [new_rapl_dram_sample[skt] - self.rapl_dram_sample[skt]
                     for skt in self.topology.get_sockets()]
        self.rapl_dram_sample = new_rapl_dram_sample
        return rapl_diff
