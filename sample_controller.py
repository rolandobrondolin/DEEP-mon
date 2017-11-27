class SampleController:

    def __init__(self, processors):
        self.timeslice = 1000000000
        self.sleep_time = 1
        self.processors = processors

    def compute_sleep_time(self, sched_switches):
        if sched_switches/(self.processors*self.sleep_time)< 100:
            self.sleep_time = 4
            self.timeslice = 4000000000
        elif sched_switches/(self.processors*self.sleep_time)< 200:
            self.sleep_time = 3
            self.timeslice = 3000000000
        elif sched_switches/(self.processors*self.sleep_time)< 300:
            self.sleep_time = 2
            self.timeslice = 2000000000
        else:
            self.sleep_time = 1
            self.timeslice = 1000000000

    def get_sleep_time(self):
        #return self.sleep_time
        return 1

    def get_timeslice(self):
        #return self.timeslice
        return 1000000000
