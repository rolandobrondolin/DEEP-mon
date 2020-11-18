"""
    DEEP-mon
    Copyright (C) 2020  Brondolin Rolando

    This file is part of DEEP-mon

    DEEP-mon is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DEEP-mon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

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
        return self.sleep_time

    def get_timeslice(self):
        return self.timeslice
