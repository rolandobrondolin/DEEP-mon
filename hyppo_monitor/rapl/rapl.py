from collections import namedtuple
from datetime import datetime


class RaplReader():

    def _read_sysfs_file(self, path):
        try:
            with open(path, "r") as f:
                contents = f.read().strip()
                return contents
        except EnvironmentError:
            return "0"

    def read_energy_core_sample(self, package=0):
        energy = int(self._read_sysfs_file("/sys/class/powercap/intel-rapl/" +
            "intel-rapl:{}/intel-rapl:{}:0/energy_uj".format(package, package)))
        return RaplSample(energy, datetime.now())

    def read_energy_dram_sample(self, package=0):
        energy = int(self._read_sysfs_file("/sys/class/powercap/intel-rapl/" +
            "intel-rapl:{}/intel-rapl:{}:1/energy_uj".format(package, package)))
        return RaplSample(energy, datetime.now())

    def read_energy_package_sample(self, package=0):
        energy = int(self._read_sysfs_file("/sys/class/powercap/intel-rapl/" +
            "intel-rapl:{}/energy_uj".format(package)))
        return RaplSample(energy, datetime.now())


class RaplSample():
    def __init__(self, energy, timestamp):
        self.energy_uj = energy
        self.sample_time = timestamp

    @property
    def energy(self):
        return self.energy_uj

    @property
    def time(self):
        return self.sample_time

    def __sub__(self, other):
        energy_diff = self.energy_uj - other.energy_uj
        delta_time = (self.sample_time - other.sample_time).total_seconds()
        # this is overflow!
        if energy_diff < 0 and delta_time > 0:
            energy_diff = 2**32 + self.energy_uj - other.energy_uj
        return RaplDiff(energy_diff, delta_time)


class RaplDiff():
    def __init__(self, energy, time):
        self.energy_uj = energy
        self.duration = time

    @property
    def energy(self):
        return self.energy_uj

    def power_w(self):
        # Convert from microJ to J and return power consumption
        return (self.energy_uj / 1000000) / self.duration

    def power_milliw(self):
        # Convert from microJ to milliJ and return power consumption
        return (self.energy_uj / 1000) / self.duration

    def power_microw(self):
        return self.energy_uj / self.duration


class RaplMonitor():

    def __init__(self, topology):
        self.rapl_reader = RaplReader()
        self.topology = topology
        self.sample_core = [self.rapl_reader.read_energy_core_sample(skt)
                            for skt in self.topology.get_sockets()]
        self.sample_pkg = [self.rapl_reader.read_energy_package_sample(skt)
                          for skt in self.topology.get_sockets()]
        self.sample_dram = [self.rapl_reader.read_energy_dram_sample(skt)
                            for skt in self.topology.get_sockets()]

    def take_sample_package(self):
        package_sample = [self.rapl_reader.read_energy_package_sample(skt)
                          for skt in self.topology.get_sockets()]
        return package_sample

    def take_sample_core(self):
        core_sample = [self.rapl_reader.read_energy_core_sample(skt)
                       for skt in self.topology.get_sockets()]
        return core_sample

    def take_sample_dram(self):
        dram_sample = [self.rapl_reader.read_energy_dram_sample(skt)
                       for skt in self.topology.get_sockets()]
        return dram_sample

    def diff_samples(self, final_sample, initial_sample):
        rapl_diff = [final_sample[skt] - initial_sample[skt]
                     for skt in self.topology.get_sockets()]
        return rapl_diff

    def get_rapl_measure(self):
        ret = {}
        package_sample = self.take_sample_package()
        core_sample = self.take_sample_core()
        dram_sample = self.take_sample_dram()

        ret["package"] = self.diff_samples(package_sample, self.sample_pkg)
        ret["core"] = self.diff_samples(core_sample, self.sample_core)
        ret["dram"] = self.diff_samples(dram_sample, self.sample_dram)

        self.sample_pkg = package_sample
        self.sample_core = core_sample
        self.sample_dram = dram_sample

        return ret
