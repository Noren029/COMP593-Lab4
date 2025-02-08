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

### Imports
#import re  # Regular expressions
import sys  # Need for sys.argv command line parameters
import os  # Need for path handling
from log_matching import filter_log_by_regex  # My own module with the convenient matching function
import pandas as pd


def main():
    log_file = get_log_file_path_from_cmd_line()  # Get the file name (Step 3)
    print(f"Analyzing file:\n  {log_file}")  # Test step 3 (we can comment out later)

    # Test with a regular expression (first pass, look for sshd)
    regex = r'SSHD'
    filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=True, print_records=True)

    return
    # end of main function here


# TODO: Step 3
def get_log_file_path_from_cmd_line():
    '''Return the command line parameter giving the file name or path,
    exit with error message if no parameter or if parameter is not a file.
    '''
    if len(sys.argv) > 1:  # there is at least one argument after the program name itself
        # Get the path
        filename = sys.argv[1]
        if os.path.isfile(filename):  # Check if it's a file
            return os.path.abspath(filename)  # Expand to full path in file system
        else:
            print("Name specified on the command line is not a file. Exiting...")
            exit(0)  # Exit status code is only used in Linux/Unix systems, just leave at zero
    else:
        print("No file name specified on the command line. Exiting...")
        exit(0)  # Exit status code is only used in Linux/Unix systems, just leave at zero
    # No return statement here, all paths through the if-else statements
    # end in a return or an exit. The return statement would be "dead code".

# TODO: Steps 4-7 -- this has been moved to the separate module

# TODO: Step 8
def tally_port_traffic(log_file):
    # Dictionary where key is the port number and the value is the number of times
    # the port was seen in the file.
    by_port = {}  # initially empty

    # Treat this as pseudo-code
    # do the matching routine, same as above
        if port_number in by_port:  # Ask if the port number is already in dictionary
            by_port[port_number] += 1  # Already there, add 1 to the count
        else:
            by_port[port_number] = 1  # first time seen in log file.
    return

    return

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):

    regex = r'^(.{6}) (.*) myth.*SRC=(.*?) DST=(.*?) '+ f'DPT=({port_number})'
    traffic_records = filter_log_by_regex(log_file,regex)[1]

    traffic_df = pd.DataFrame(traffic_records)
    traffic_header = ('Date', 'Time', 'Source IP Address', 'Destination IP Adress', 'Source Port', 'Destination Port')

    Traffic_df.to_csv(f'destination_port_{port_number}_report.csv',header=traffic_header,index=False)


    return

# TODO: Step 11
def generate_invalid_user_report(log_file):
    return
pip
# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    return

if __name__ == '__main__':
     main()