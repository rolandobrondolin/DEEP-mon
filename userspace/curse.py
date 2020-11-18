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

import curses
import time
import locale

class Curse:
    def __init__(self, monitor, power_measure, net_monitor, memory_measure, disk_measure, file_measure):
        locale.setlocale(locale.LC_ALL, '')
        self.monitor = monitor
        self.pages = []
        self.displayed_metric = 'default'
        self.highlighted_line_index = 0
        self.start_display_index = 0
        self.end_display_index = 0
        self.initialize_metrics(power_measure, net_monitor, memory_measure, disk_measure, file_measure)

    def start(self):
        curses.wrapper(self.main)

    def initialize_metrics(self, power, net, memory, disk, files):
        self.pages.append('default')
        if power:
            self.pages.append("power")
        if memory:
            self.pages.append("memory")
        if disk:
            self.pages.append("disk")
        if files:
            self.pages.append("file")
        if net:
            self.pages.append("tcp")
            self.pages.append("tcp percentiles")
            self.pages.append("http")
            self.pages.append("http percentiles")

    def set_sample(self, sample):
        self.sample = sample

    def title_line(self, cx):
        title_win = curses.newwin(1,cx,0,0)

        title_str = "DEEP-mon"
        title_win.bkgd(" ", curses.color_pair(9))
        title_win.addstr(0,int(cx/2-len(title_str)/2), title_str,  curses.color_pair(9))

        #title_win.addstr(0,0, str(self.start_display_index)+" "+str(self.end_display_index)+" "+str(self.highlighted_line_index),  curses.color_pair(9))
        title_win.noutrefresh()

    def last_line(self, cx,cy):
        locale.setlocale(locale.LC_ALL, '')

        last_line_win = curses.newwin(1,cx,cy-1,0)
        last_line_str = ("Press 'q' to exit, "+chr(8592)+" or "+chr(8594)+" to change metrics page, "+chr(8593)+" or "+chr(8595)+" to change line.").encode("UTF-8")
        last_line_win.bkgd(" ", curses.color_pair(4))
        last_line_win.addstr(0,0, last_line_str, curses.color_pair(4))
        last_line_win.addstr(0, cx-2, chr(9731).encode('UTF-8'), curses.color_pair(4))
        last_line_win.noutrefresh()

    def persistent_info(self, cx, cy, log_dict):
        first_column_label_length = 21
        second_column_label_length = 29
        new_win = curses.newwin(3,cx,1,0)

        new_win.addstr(0,0, "SAMPLE TIMESLICE:", curses.color_pair(6))
        new_win.addstr(1,0, "SCHED SWITCH COUNT:", curses.color_pair(6))
        new_win.addstr(2,0, "PROC TIME:", curses.color_pair(6))

        new_win.addstr(0, first_column_label_length, "%-9s" %(log_dict["TIMESLICE"]+"s"))
        new_win.addstr(1, first_column_label_length, "%-9s" %(log_dict["SCHED SWITCH COUNT"]))
        new_win.addstr(2, first_column_label_length, "%-9s" %(log_dict["PROC TIME"]))

        new_win.addstr(0,int(cx/2), "TOTAL PACKAGE ACTIVE POWER:", curses.color_pair(2))
        new_win.addstr(1,int(cx/2), "TOTAL CORE ACTIVE POWER:", curses.color_pair(2))
        new_win.addstr(2,int(cx/2), "TOTAL DRAM ACTIVE POWER:", curses.color_pair(2))

        new_win.addstr(0, int(cx/2+second_column_label_length), "%-9s" %(log_dict["TOTAL PACKAGE ACTIVE POWER"]))
        new_win.addstr(1, int(cx/2+second_column_label_length), "%-9s" %(log_dict["TOTAL CORE ACTIVE POWER"]))
        new_win.addstr(2, int(cx/2+second_column_label_length), "%-9s" %(log_dict["TOTAL DRAM ACTIVE POWER"]))

        new_win.noutrefresh()

    def label_line(self, cx):
        label_win = curses.newwin(2,cx,4,0)
        label_win.bkgd(" ", curses.color_pair(7) | curses.A_REVERSE)

        label_win.addstr(0,0, "Displaying %s metrics" %(self.displayed_metric))
        label_win.addstr(0,cx-10, "Page %d/%d" %(self.pages.index(self.displayed_metric)+1, len(self.pages)))

        if (self.displayed_metric == 'default'):
            label_win.addstr(1,0, "%12s %40s %12s %12s" % (
            "CONTAINER_ID", "CONTAINER_NAME", "EXEC TIME(s)", "CPU USAGE"
            ))
        elif (self.displayed_metric == 'power'):
            label_win.addstr(1,0, "%12s %40s %11s %11s %10s %10s %9s %10s" % (
            "CONTAINER_ID", "CONTAINER_NAME", "CYCLES", "W_CYCLES", "INSTR_RET", "CACHE_MISS", "CACHE_REF", "TOT_POWER"
            ))
        elif (self.displayed_metric == 'memory'):
            label_win.addstr(1,0, "%12s %40s %11s %11s %11s" % (
            "CONTAINER_ID", "CONTAINER_NAME", "RSS (Kb)", "PSS (Kb)", "USS (Kb)"
            ))
        elif (self.displayed_metric == 'disk'):
            label_win.addstr(1,0, "%12s %40s %11s %11s %11s %11s %11s" % (
            "CONTAINER_ID", "CONTAINER_NAME", "Kb_R", "Kb_W", "NUM_R", "NUM_W", "AVG_LAT(ms)"
            ))
        elif (self.displayed_metric == 'tcp'):
            label_win.addstr(1,0, "%12s %40s %13s %14s %14s %13s" % (
            "CONTAINER_ID", "CONTAINER_NAME", "TCP_T_COUNT", "TCP_BYTE_SENT", "TCP_BYTE_RECV", "AVG_LAT(ms)"
            ))
        elif (self.displayed_metric == 'http'):
            label_win.addstr(1,0, "%12s %40s %13s %14s %14s %13s" % (
            "CONTAINER_ID", "CONTAINER_NAME", "HTTP_T_COUNT", "HTTP_BYTE_SENT", "HTTP_BYTE_RECV", "AVG_LAT(ms)"
            ))
        elif (self.displayed_metric == 'tcp percentiles'):
            label_win.addstr(1,0, "%12s %40s %8s %8s %8s %8s %8s %8s %8s" % (
            "CONTAINER_ID", "CONTAINER_NAME", "50p", "75p", "90p", "99p", "99.9p", "99.99p", "99.999p"
            ))
        elif (self.displayed_metric == 'http percentiles'):
            label_win.addstr(1,0, "%12s %40s %8s %8s %8s %8s %8s %8s %8s" % (
            "CONTAINER_ID", "CONTAINER_NAME", "50p", "75p", "90p", "99p", "99.9p", "99.99p", "99.999p"
            ))
        elif (self.displayed_metric == 'file'):
            label_win.addstr(1,0, "%11s %11s %11s %11s %s" % (
                "Kb_R", "Kb_W", "NUM_R", "NUM_W", "FILE NAME"
            ))


        label_win.noutrefresh()

    def metrics_window(self, cx, cy, container_list, file_dict):
        metrics_win = curses.newwin(cy-6,cx,6,0)

        counter = 0
        if self.displayed_metric != "file":
            for key, value in sorted(container_list.items()):
                if (counter == self.highlighted_line_index):
                    color = curses.color_pair(4)
                else:
                    color = curses.color_pair(8)
                if (self.start_display_index <= counter < self.end_display_index):
                    metrics_win.addstr(counter-self.start_display_index, 0, "%12s " %key, color)

                    if value.get_container_name() != None:
                        metrics_win.addstr(counter-self.start_display_index, 13, "%41s" % value.get_container_name().ljust(40)[0:40], color)
                    else:
                        metrics_win.addstr(counter-self.start_display_index, 13, "%41s" %"", color)

                    if self.displayed_metric == 'default':
                        metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%12s %12s " % (
                        '{:.5f}'.format(value.get_time_ns() / 1000000000.0),
                        '{:.2f}'.format(value.get_cpu_usage())
                        ),cx-54), color)

                    elif self.displayed_metric == 'power':
                        metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%11d %11d %10d %10s %9s %8smW" % (
                        value.get_cycles(), value.get_weighted_cycles(),
                        value.get_instruction_retired(),
                        value.get_cache_misses(), value.get_cache_refs(),
                        '{:.2f}'.format(value.get_power())
                        ),cx-54), color)

                    elif self.displayed_metric == 'memory':
                        metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%11s %11s %11s" % (
                        str(value.get_mem_RSS()), str(value.get_mem_PSS()), str(value.get_mem_USS())
                        ),cx-54), color)

                    elif self.displayed_metric == 'disk':
                        metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%11s %11s %11s %11s %11s" % (
                        str(value.get_kb_r()), str(value.get_kb_w()),
                        str(value.get_num_r()), str(value.get_num_w()),
                        '{:.3f}'.format(value.get_disk_avg_lat())
                        ),cx-54), color)

                    elif self.displayed_metric == 'http':
                        metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%13s %14s %14s %13s" % (
                        str(value.get_http_transaction_count()), str(value.get_http_byte_tx()),
                        str(value.get_http_byte_rx()), '{:.2f}'.format(value.get_http_avg_latency()),
                        ),cx-54), color)

                    elif self.displayed_metric == 'tcp':
                        metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%13s %14s %14s %13s" % (
                        str(value.get_tcp_transaction_count()), str(value.get_tcp_byte_tx()),
                        str(value.get_tcp_byte_rx()), '{:.2f}'.format(value.get_tcp_avg_latency()),
                        ),cx-54), color)

                    elif self.displayed_metric == 'http percentiles':
                        pct_val = value.get_http_percentiles()[1]
                        if len(pct_val) == 7:
                            metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%8s %8s %8s %8s %8s %8s %8s" % (
                            '{:.1f}'.format(pct_val[0]), '{:.1f}'.format(pct_val[1]),
                            '{:.1f}'.format(pct_val[2]), '{:.1f}'.format(pct_val[3]),
                            '{:.1f}'.format(pct_val[4]), '{:.1f}'.format(pct_val[5]),
                            '{:.1f}'.format(pct_val[6])
                            ),cx-54), color)
                        else:
                            metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%8s %8s %8s %8s %8s %8s %8s" % (
                            '0', '0', '0', '0', '0', '0', '0'
                            ),cx-54), color)

                    elif self.displayed_metric == 'tcp percentiles':
                        pct_val = value.get_tcp_percentiles()[1]
                        if len(pct_val) == 7:
                            metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%8s %8s %8s %8s %8s %8s %8s" % (
                            '{:.1f}'.format(pct_val[0]), '{:.1f}'.format(pct_val[1]),
                            '{:.1f}'.format(pct_val[2]), '{:.1f}'.format(pct_val[3]),
                            '{:.1f}'.format(pct_val[4]), '{:.1f}'.format(pct_val[5]),
                            '{:.1f}'.format(pct_val[6])
                            ),cx-54), color)
                        else:
                            metrics_win.addstr(counter-self.start_display_index, 54, str.ljust("%8s %8s %8s %8s %8s %8s %8s" % (
                            '0', '0', '0', '0', '0', '0', '0'
                            ),cx-54), color)
                counter += 1
        else:
            for key, value in reversed(sorted(file_dict.items(), key=lambda counts: counts[1].get_kb_r()+counts[1].get_kb_w())):
                if (counter == self.highlighted_line_index):
                    color = curses.color_pair(4)
                else:
                    color = curses.color_pair(8)
                if (self.start_display_index <= counter < self.end_display_index):
                    str_key = key
                    if (len(key)>cx-50):
                        str_key= ".."+key[-(cx-50):]
                    metrics_win.addstr(counter-self.start_display_index, 0, str.ljust("%11s %11s %11s %11s %s" % (
                        str(file_dict[key].get_kb_r()), str(file_dict[key].get_kb_w()),
                        str(file_dict[key].get_num_r()), str(file_dict[key].get_num_w()),
                        str_key),cx), color)
                counter += 1

        metrics_win.noutrefresh()

    def _reset_window_indices(self, stdscr):
        yx = stdscr.getmaxyx()
        cy = yx[0]
        self.highlighted_line_index = 0
        self.start_display_index = 0
        self.end_display_index = cy-7

    def main(self, stdscr):
        if self.monitor.get_window_mode() == 'dynamic':
            time_to_sleep = self.monitor.get_sample_controller().get_sleep_time()
        else:
            time_to_sleep = 1

        stdscr.nodelay(True)
        stdscr.timeout(100)
        curses.curs_set(False)

        bg_color = curses.COLOR_BLACK
        if curses.has_colors():
            curses.init_pair(1, curses.COLOR_RED, bg_color)
            curses.init_pair(2, curses.COLOR_GREEN, bg_color)
            curses.init_pair(3, curses.COLOR_BLUE, bg_color)
            curses.init_pair(4, bg_color, curses.COLOR_WHITE)
            curses.init_pair(5, curses.COLOR_MAGENTA, bg_color)
            curses.init_pair(6, curses.COLOR_YELLOW, bg_color)
            curses.init_pair(7, curses.COLOR_CYAN, bg_color)
            curses.init_pair(8, curses.COLOR_WHITE, bg_color)
            curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_RED)

        previous_time = time.time()
        sample_array = self.monitor.get_sample()
        sample = sample_array[0]
        container_list = sample_array[1]

        yx = stdscr.getmaxyx()
        cx = yx[1]
        cy = yx[0]

        self.start_display_index = 0
        self.end_display_index = cy-7

        while True:
            start_time = time.time()
            curses.napms(5)

            if (start_time - previous_time > time_to_sleep):
                sample_array = self.monitor.get_sample()
                sample = sample_array[0]
                container_list = sample_array[1]
                file_dict = sample_array[4]
                previous_time = time.time()
                if self.monitor.get_window_mode() == 'dynamic':
                    time_to_sleep = self.monitor.get_sample_controller().get_sleep_time() \
                        - (time.time() - start_time)
                else:
                    time_to_sleep = 1 - (time.time() - start_time)

            yx = stdscr.getmaxyx()
            cx = yx[1]
            cy = yx[0]

            if (cx >= 120 and cy >= 7):
                self.title_line(cx)
                self.persistent_info(cx,cy, sample.get_log_dict())
                self.metrics_window(cx,cy, container_list, file_dict)
                self.label_line(cx)
                self.last_line(cx,cy)
            else:
                stdscr.clear()
                stdscr.addstr(5,1, "Window too small, try to resize :(")
                stdscr.refresh()

            ch = stdscr.getch()

            if ch == ord('q'):
                return 0
            elif ch == curses.KEY_LEFT:
                self.displayed_metric = self.pages[(self.pages.index(self.displayed_metric)-1) % len(self.pages)]
                self._reset_window_indices(stdscr)
            elif ch == curses.KEY_RIGHT:
                self.displayed_metric = self.pages[(self.pages.index(self.displayed_metric)+1) % len(self.pages)]
                self._reset_window_indices(stdscr)

            elif ch == curses.KEY_UP:
                if self.highlighted_line_index >= self.start_display_index and self.highlighted_line_index > 0:
                    self.highlighted_line_index -= 1
                if self.highlighted_line_index == self.start_display_index-1 and self.start_display_index > 0:
                    self.start_display_index -= 1
                    self.end_display_index -= 1
            elif ch == curses.KEY_DOWN:
                if (self.displayed_metric != 'file' and self.highlighted_line_index < min(self.end_display_index, len(container_list)-1)):
                    self.highlighted_line_index += 1
                elif (self.displayed_metric == 'file' and self.highlighted_line_index < min(self.end_display_index, len(file_dict)-1)):
                    self.highlighted_line_index += 1
                if (self.displayed_metric != 'file' and self.highlighted_line_index >= (cy-7) and self.end_display_index < len(container_list)):
                    self.start_display_index += 1
                    self.end_display_index += 1
                elif (self.displayed_metric == 'file' and self.highlighted_line_index >= (cy-7) and self.end_display_index < len(file_dict)):
                    self.start_display_index += 1
                    self.end_display_index += 1

            elif ch == curses.KEY_RESIZE:
                self._reset_window_indices(stdscr)


            curses.doupdate()
