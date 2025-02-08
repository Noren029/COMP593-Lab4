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

# Import necessary modules
import sys  # Need for sys.argv command line parameters
import os  # Need for path handling
import re  # Regular expressions
import pandas as pd
import csv
from log_matching import filter_log_by_regex  # Your custom function for matching logs

# Main function that orchestrates the script's operations
def main():
    log_file = get_log_file_path_from_cmd_line()  # Get the file name (Step 3)
    print(f"Analyzing file:\n  {log_file}")  # Test step 3 (we can comment out later)

    # Test with a regular expression (first pass, look for sshd)
    regex = r'SSHD'
    filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=True, print_records=True)

    # Uncomment the below line to test additional functionalities
    # tally_port_traffic(log_file)  # Step 8
    # generate_port_traffic_report(log_file, 22)  # Step 9, Example with port 22 (SSH)
    # generate_invalid_user_report(log_file)  # Step 11
    # generate_source_ip_log(log_file, '192.168.1.1')  # Step 12, Example with a source IP address

# Step 3: Retrieve log file path from the command line
def get_log_file_path_from_cmd_line():
    '''Return the command line parameter giving the file name or path,
    exit with error message if no parameter or if parameter is not a file.'''
    if len(sys.argv) > 1:  # there is at least one argument after the program name itself
        filename = sys.argv[1]
        if os.path.isfile(filename):  # Check if it's a file
            return os.path.abspath(filename)  # Return the absolute path
        else:
            print("Name specified on the command line is not a file. Exiting...")
            exit(0)
    else:
        print("No file name specified on the command line. Exiting...")
        exit(0)

# Step 8: Tally the traffic for each port
def tally_port_traffic(log_file):
    by_port = {}  # Dictionary to store port number and its count

    try:
        with open(log_file, 'r') as file:
            records = file.readlines()

        for record in records:
            match = re.search(r'DPT=(\d+)', record)  # Search for the destination port
            if match:
                port_number = match.group(1)
                if port_number in by_port:
                    by_port[port_number] += 1
                else:
                    by_port[port_number] = 1

        print("Port Traffic Tally:")
        for port, count in by_port.items():
            print(f"Port {port}: {count} occurrences")

    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
        exit(1)

# Step 9: Generate a port traffic report based on the port number
def generate_port_traffic_report(log_file, port_number):
    regex = r'^(.{6}) (.*) myth.*SRC=(.*?) DST=(.*?) DPT=' + f'({port_number})'

    traffic_records = filter_log_by_regex(log_file, regex)[1]

    # Create a DataFrame for the traffic records
    traffic_df = pd.DataFrame(traffic_records, columns=['Date', 'Time', 'Source IP Address', 'Destination IP Address', 'Source Port', 'Destination Port'])

    # Save the DataFrame to a CSV file
    traffic_df.to_csv(f'destination_port_{port_number}_report.csv', header=True, index=False)
    print(f"Port traffic report saved as destination_port_{port_number}_report.csv")

# Step 11: Generate an invalid user report
def generate_invalid_user_report(log_file):
    '''Generate a report for invalid user logins.'''
    regex = r"Invalid user (\S+)"
    matching_records = filter_log_by_regex(log_file, regex)[1]

    # Save the report to a CSV file
    with open('invalid_user_report.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['Invalid Username', 'Log Message'])

        for record in matching_records:
            match = re.search(r"Invalid user (\S+)", record)
            if match:
                writer.writerow([match.group(1), record.strip()])

    print("Invalid User Report saved as invalid_user_report.csv")

# Step 12: Generate a log for a specific source IP address
def generate_source_ip_log(log_file, ip_address):
    '''Generate a log for a specific source IP address.'''
    regex = f"src={ip_address}"
    matching_records = filter_log_by_regex(log_file, regex)[1]

    # Save the source IP log to a CSV file
    with open(f'source_ip_log_{ip_address}.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['Source IP', 'Log Message'])

        for record in matching_records:
            writer.writerow([ip_address, record.strip()])

    print(f"Source IP log saved as source_ip_log_{ip_address}.csv")

# Entry point for script execution
if __name__ == '__main__':
    main()