'''log_analysis.py - Analyze a network gateway log file using regular expressions.
COMP 593 Scripting Applications - Winter 2025 (Week 5)
Louis Bertrand <louis.bertrand@flemingcollege.ca>

Usage:
    python log_analysis <logfile>
    where <logfile> is the file name or path to the log file.

### STUDENTS: PLEASE ADD THE STANDARD ACADEMIC INTEGRITY STATEMENT.###
# This program is strictly my own work. Any material beyond course learning
# materials that is taken from the Web or other sources is properly cited,
# giving credit to the original author(s).

'''


from log_matching import get_log_file_path_from_cmd_line,filter_log_by_regex
import pandas as pd

def main():
    log_file = get_log_file_path_from_cmd_line()

    regex =r'sshd'
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)

    regex =r'invalid user.*220.195.35.40'
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)

    regex =r'error' 
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)

    regex =r'pam'
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)

    regex =r'invalid user'
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)





# TODO: Step 8
def tally_port_traffic(log_file):
    return

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):
    return

# TODO: Step 11
def generate_invalid_user_report(log_file):
    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    return

if __name__ == '__main__':
        main()