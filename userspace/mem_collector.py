import os

class MemCollector:
    def __init__ (self):
        self.mem_dictionary = dict()
        self.proc_path = "/host/proc"

    def get_mem_dictionary(self):
        self.mem_dictionary = self._aggregate_mem_metrics(self._get_sample())
        return self.mem_dictionary

    def _get_pid_list(self):
        pid_list = os.listdir(self.proc_path)
        return [int(x) for x in pid_list if x.isdigit()]

    def _aggregate_mem_metrics(self, mem_sample):
        container_dict = dict()
        for pid in mem_sample:
            shortened_ID = mem_sample[pid]["container_ID"][:12]
            if shortened_ID not in container_dict:
                container_dict[shortened_ID] = {}
                container_dict[shortened_ID]["full_ID"] = mem_sample[pid]["container_ID"]
                container_dict[shortened_ID]["RSS"] = 0
                container_dict[shortened_ID]["PSS"] = 0
                container_dict[shortened_ID]["USS"] = 0
                container_dict[shortened_ID]["pids"] = []
            container_dict[shortened_ID]["RSS"] += mem_sample[pid]["RSS"]
            container_dict[shortened_ID]["PSS"] += mem_sample[pid]["PSS"]
            container_dict[shortened_ID]["USS"] += mem_sample[pid]["USS"]
            container_dict[shortened_ID]["pids"].append(pid)
        return container_dict

    def _get_sample(self):
        pid_dict = dict()
        for pid in self._get_pid_list():
            pid_dict[pid] = {}
            pid_dict[pid]["RSS"] = 0
            pid_dict[pid]["USS"] = 0
            pid_dict[pid]["PSS"] = 0
            pid_dict[pid]["container_ID"] = "---others---"
            #USS and PSS from smaps_rollup
            if (os.path.exists(os.path.join(self.proc_path,str(pid),"smaps_rollup"))):
                try:
                    with open(os.path.join(self.proc_path,str(pid),"smaps_rollup"),"r") as f:
                        for line in f:
                            s = line.replace(" ","").replace("\n","").split(':')
                            if (s[0] == "Rss"):
                                pid_dict[pid]["RSS"] = int(s[1][:-2])
                            elif (s[0] == "Pss"):
                                pid_dict[pid]["PSS"] = int(s[1][:-2])
                            elif (s[0] == "Private_Clean" or s[0] == "Private_Dirty" or s[0] == "Private_Hugetlb"):
                                pid_dict[pid]["USS"] += int(s[1][:-2])
                except IOError:
                    continue
            #USS and PSS from smaps when smaps_rollup isn't in proc
            else:
                try:
                    with open(os.path.join(self.proc_path,str(pid),"smaps"),"r") as f:
                        for line in f:
                            s = line.replace(" ","").replace("\n","").split(':')
                            if (s[0] == "Pss"):
                                pid_dict[pid]["RSS"] += int(s[1][:-2])
                            elif (s[0] == "Pss"):
                                pid_dict[pid]["PSS"] += int(s[1][:-2])
                            elif (s[0] == "Private_Clean" or s[0] == "Private_Dirty" or s[0] == "Private_Hugetlb"):
                                pid_dict[pid]["USS"] += int(s[1][:-2])
                except IOError:
                    continue
            #assign container ID from proc
            if (os.path.exists(os.path.join(self.proc_path,str(pid),"cgroup"))):
                try:
                    with open(os.path.join(self.proc_path, str(pid), 'cgroup'), 'r') as f:
                        for line in f:
                            line_array = line.split("/")
                            if len(line_array) > 1 and \
                                len(line_array[len(line_array) -1]) == 65:
                                pid_dict[pid]["container_ID"] = line_array[len(line_array) -1][:-1]
                except IOError:
                    continue
                # systemd Docker
                try:
                    with open(os.path.join(self.proc_path, str(pid), 'cgroup'), 'r') as f:
                        for line in f:
                            line_array = line.split("/")
                            if len(line_array) > 1 \
                                and "docker-" in line_array[len(line_array) -1] \
                                and ".scope" in line_array[len(line_array) -1]:

                                new_id = line_array[len(line_array) -1].replace("docker-", "")
                                new_id = new_id.replace(".scope", "")
                                if len(new_id) == 65:
                                    pid_dict[pid]["container_ID"] = new_id
                except IOError:
                    continue

        return pid_dict
