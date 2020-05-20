import curses
import time
import locale

class Curse:
    def __init__(self, monitor, power_measure, net_monitor, memory_measure, disk_measure):
        locale.setlocale(locale.LC_ALL, '')
        self.monitor = monitor
        self.pages = []
        self.displayed_metric = 'default'
        self.highlighted_line_index = 0
        self.initialize_metrics(power_measure, net_monitor, memory_measure, disk_measure)

    def start(self):
        curses.wrapper(self.main)

    def initialize_metrics(self, power, net, memory, disk):
        self.pages.append('default')
        if power:
            self.pages.append("power")
        if memory:
            self.pages.append("memory")
        if disk:
            self.pages.append("disk")
        if net:
            self.pages.append("tcp")
            self.pages.append("tcp percentiles")
            self.pages.append("http")
            self.pages.append("http percentiles")

    def set_sample(self, sample):
        self.sample = sample

    def title_line(self, cx):
        title_win = curses.newwin(1,cx,0,0)

        title_str = "HYPPO Standalone Monitor"
        title_win.bkgd(" ", curses.color_pair(9))
        title_win.addstr(0,cx/2-len(title_str)/2, title_str,  curses.color_pair(9))
        title_win.noutrefresh()

    def last_line(self, cx,cy):
        locale.setlocale(locale.LC_ALL, '')

        last_line_win = curses.newwin(1,cx,cy-1,0)
        last_line_str = ("Press 'q' to exit, "+unichr(8592)+" or "+unichr(8594)+" to change metrics page, "+unichr(8593)+" or "+unichr(8595)+" to change line.").encode("UTF-8")
        last_line_win.bkgd(" ", curses.color_pair(4))
        last_line_win.addstr(0,0, last_line_str, curses.color_pair(4))
        last_line_win.addstr(0, cx-2, unichr(9731).encode('UTF-8'), curses.color_pair(4))
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

        new_win.addstr(0,cx/2, "TOTAL PACKAGE ACTIVE POWER:", curses.color_pair(2))
        new_win.addstr(1,cx/2, "TOTAL CORE ACTIVE POWER:", curses.color_pair(2))
        new_win.addstr(2,cx/2, "TOTAL DRAM ACTIVE POWER:", curses.color_pair(2))

        new_win.addstr(0, cx/2+second_column_label_length, "%-9s" %(log_dict["TOTAL PACKAGE ACTIVE POWER"]))
        new_win.addstr(1, cx/2+second_column_label_length, "%-9s" %(log_dict["TOTAL CORE ACTIVE POWER"]))
        new_win.addstr(2, cx/2+second_column_label_length, "%-9s" %(log_dict["TOTAL DRAM ACTIVE POWER"]))

        new_win.noutrefresh()

    def label_line(self, cx):
        label_win = curses.newwin(2,cx,4,0)
        label_win.bkgd(" ", curses.color_pair(7) | curses.A_REVERSE)

        label_win.addstr(0,0, "Displaying %s metrics" %(self.displayed_metric))
        label_win.addstr(0,cx-10, "Page %d/%d" %(self.pages.index(self.displayed_metric)+1, len(self.pages)))

        if (self.displayed_metric == 'default'):
            label_win.addstr(1,0, "%12s %12s %12s" % (
            "CONTAINER_ID", "EXEC TIME(s)", "CPU USAGE"
            )) 
        elif (self.displayed_metric == 'power'):
            label_win.addstr(1,0, "%12s %11s %11s %10s %10s %9s %10s" % (
            "CONTAINER_ID", "CYCLES", "W_CYCLES", "INSTR_RET", "CACHE_MISS", "CACHE_REF", "TOT_POWER"
            )) 
        elif (self.displayed_metric == 'memory'):
            label_win.addstr(1,0, "%12s %11s %11s %11s" % (
            "CONTAINER_ID", "RSS (Kb)", "PSS (Kb)", "USS (Kb)"
            )) 
        elif (self.displayed_metric == 'disk'):
            label_win.addstr(1,0, "%12s %11s %11s %11s %11s %11s" % (
            "CONTAINER_ID", "Kb_R", "Kb_W", "NUM_R", "NUM_W", "AVG_LAT(ms)"
            )) 
        elif (self.displayed_metric == 'tcp'):
            label_win.addstr(1,0, "%12s %13s %14s %14s %13s" % (
            "CONTAINER_ID", "TCP_T_COUNT", "TCP_BYTE_SENT", "TCP_BYTE_RECV", "AVG_LAT(ms)"
            ))
        elif (self.displayed_metric == 'http'):
            label_win.addstr(1,0, "%12s %13s %14s %14s %13s" % (
            "CONTAINER_ID", "HTTP_T_COUNT", "HTTP_BYTE_SENT", "HTTP_BYTE_RECV", "AVG_LAT(ms)"
            ))
        elif (self.displayed_metric == 'tcp percentiles'):
            label_win.addstr(1,0, "%12s %8s %8s %8s %8s %8s %8s %8s" % (
            "CONTAINER_ID", "50p", "75p", "90p", "99p", "99.9p", "99.99p", "99.999p"
            ))
        elif (self.displayed_metric == 'http percentiles'):
            label_win.addstr(1,0, "%12s %8s %8s %8s %8s %8s %8s %8s" % (
            "CONTAINER_ID", "50p", "75p", "90p", "99p", "99.9p", "99.99p", "99.999p"
            ))


        label_win.noutrefresh()

    def metrics_window(self, cx, cy, container_list):
        metrics_win = curses.newwin(cy-6,cx,6,0)
        
        counter = 0
        for key, value in sorted(container_list.items()):
            if (counter == self.highlighted_line_index):
                color = curses.color_pair(4)
            else:
                color = curses.color_pair(8)

            metrics_win.addstr(counter, 0, "%12s " %key, color)

            if self.displayed_metric == 'default':
                metrics_win.addstr(counter, 13, str.ljust("%12s %12s " % (
                '{:.5f}'.format(value.get_time_ns() / 1000000000.0),
                '{:.2f}'.format(value.get_cpu_usage())
                ),cx-13), color)

            elif self.displayed_metric == 'power':
                metrics_win.addstr(counter, 13, str.ljust("%11d %11d %10d %10s %9s %8smW" % (
                value.get_cycles(), value.get_weighted_cycles(),
                value.get_instruction_retired(),
                value.get_cache_misses(), value.get_cache_refs(),
                '{:.2f}'.format(value.get_power())
                ),cx-13), color)

            elif self.displayed_metric == 'memory':
                metrics_win.addstr(counter, 13, str.ljust("%11s %11s %11s" % (
                str(value.get_mem_RSS()), str(value.get_mem_PSS()), str(value.get_mem_USS())
                ),cx-13), color)
            
            elif self.displayed_metric == 'disk':
                metrics_win.addstr(counter, 13, str.ljust("%11s %11s %11s %11s %11s" % (
                str(value.get_kb_r()), str(value.get_kb_w()),
                str(value.get_num_r()), str(value.get_num_w()),
                '{:.3f}'.format(value.get_disk_avg_lat())
                ),cx-13), color)

            elif self.displayed_metric == 'http':
                metrics_win.addstr(counter, 13, str.ljust("%13s %14s %14s %13s" % (
                str(value.get_http_transaction_count()), str(value.get_http_byte_tx()),
                str(value.get_http_byte_rx()), '{:.2f}'.format(value.get_http_avg_latency()),
                ),cx-13), color)

            elif self.displayed_metric == 'tcp':
                metrics_win.addstr(counter, 13, str.ljust("%13s %14s %14s %13s" % (
                str(value.get_tcp_transaction_count()), str(value.get_tcp_byte_tx()),
                str(value.get_tcp_byte_rx()), '{:.2f}'.format(value.get_tcp_avg_latency()),
                ),cx-13), color)

            elif self.displayed_metric == 'http percentiles':
                pct_val = value.get_http_percentiles()[1]
                if len(pct_val) == 7:
                    metrics_win.addstr(counter, 13, str.ljust("%8s %8s %8s %8s %8s %8s %8s" % (
                    '{:.1f}'.format(pct_val[0]), '{:.1f}'.format(pct_val[1]),
                    '{:.1f}'.format(pct_val[2]), '{:.1f}'.format(pct_val[3]),
                    '{:.1f}'.format(pct_val[4]), '{:.1f}'.format(pct_val[5]),
                    '{:.1f}'.format(pct_val[6]) 
                    ),cx-13), color)
                else:
                    metrics_win.addstr(counter, 13, str.ljust("%8s %8s %8s %8s %8s %8s %8s" % (
                    '0', '0', '0', '0', '0', '0', '0'
                    ),cx-13), color)

            elif self.displayed_metric == 'tcp percentiles':
                pct_val = value.get_tcp_percentiles()[1]
                if len(pct_val) == 7:
                    metrics_win.addstr(counter, 13, str.ljust("%8s %8s %8s %8s %8s %8s %8s" % (
                    '{:.1f}'.format(pct_val[0]), '{:.1f}'.format(pct_val[1]),
                    '{:.1f}'.format(pct_val[2]), '{:.1f}'.format(pct_val[3]),
                    '{:.1f}'.format(pct_val[4]), '{:.1f}'.format(pct_val[5]),
                    '{:.1f}'.format(pct_val[6]) 
                    ),cx-13), color)
                else:
                    metrics_win.addstr(counter, 13, str.ljust("%8s %8s %8s %8s %8s %8s %8s" % (
                    '0', '0', '0', '0', '0', '0', '0'
                    ),cx-13), color)

            counter += 1

        metrics_win.noutrefresh()


    def main(self, stdscr):
        if self.monitor.get_window_mode() == 'dynamic':
            time_to_sleep = self.monitor.get_sample_controller().get_sleep_time()
        else:
            time_to_sleep = 1

        stdscr.nodelay(True)
        stdscr.timeout(0)
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

        while True:
            start_time = time.time()
            curses.napms(10)
            
            if (start_time - previous_time > time_to_sleep):
                sample_array = self.monitor.get_sample()
                sample = sample_array[0]
                container_list = sample_array[1]
                previous_time = time.time()
                if self.monitor.get_window_mode() == 'dynamic':
                    time_to_sleep = self.monitor.get_sample_controller().get_sleep_time() \
                        - (time.time() - start_time)
                else:
                    time_to_sleep = 1 - (time.time() - start_time)

            yx = stdscr.getmaxyx()
            cx = yx[1]
            cy = yx[0]

            if (cx >= 80 and cy >= 5):
                self.title_line(cx)
                self.persistent_info(cx,cy, sample.get_log_dict())
                self.metrics_window(cx,cy, container_list)
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
            elif ch == curses.KEY_RIGHT:
                self.displayed_metric = self.pages[(self.pages.index(self.displayed_metric)+1) % len(self.pages)]
            elif ch == curses.KEY_UP:
                self.highlighted_line_index = (self.highlighted_line_index-1)%len(container_list)
            elif ch == curses.KEY_DOWN:
                self.highlighted_line_index = (self.highlighted_line_index+1)%len(container_list)

            curses.doupdate()
        