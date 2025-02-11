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

from log_matching import get_log_file_path_from_cmd_line, filter_log_by_regex
import re
import pandas as pd

def main():
    log_file = get_log_file_path_from_cmd_line()
    
    regex = r"SSHD"
    filter_log_by_regex(log_file,regex, ignore_case=True,print_summary=True, print_records=True)

    regex2 =r'invalid user.*220.195.35.40'
    filter_log_by_regex(log_file,regex2, ignore_case=True,print_summary=True, print_records=True)

    regex3 = 'error'
    filter_log_by_regex(log_file,regex3, ignore_case=True,print_summary=True, print_records=True)

 # step 8

    port_traffic = tally_port_traffic(log_file)

# step 10
    for port, count in port_traffic.items():
        
        if (count >=100 ):
            print(f'Port {port} has traffic greater than or equal to 100, it is {count}')
        # TODO Generate Port traffic report

# TODO: Step 8
def tally_port_traffic(log_file):
    port_traffic = {}

    with open(log_file, 'r')as file:
        for record in file: # iterate line by line
            match = re.search(r'DPT=([^]*)', record)

            if match:
                port = match.group(1)
                port_traffic[port]=port_traffic.get(port,0)+1

    return port_traffic

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):

    regex = r'^(.{6}) (.*) myth.*SRC=(.*?) DST=(.*?) .*SPT(.*?)  '+f'DPT=({port_number})'
    traffic_records = filter_log_by_regex(log_file,regex)[1]
    
    traffic_df = pd.DataFrame(traffic_records)
    traffic_header = ('Date', 'Time', 'Source IP Address', 'Source Port', 'Destination Port'  )
    
    traffic_df.to_csv(f'destination_port_{port_number}_report.csv',header=traffic_header,index=False)

    return

# TODO: Step 11
def generate_invalid_user_report(log_file):

    regex = r'^(.{6}) (.*) myth sshd.{6}.: Invalid user anonymous from 220.195.35.40)  '
    invalid_user = filter_log_by_regex(log_file,regex)[1]

    invalid_df = pd.DataFrame(invalid_user)
    invalid_header = ('Date', 'Time', 'Username', 'IP Address'  )

    invalid_df.to_csv(f'Invalid_user_report.csv', header=invalid_header, index=False)
    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address): # Step 12: Function to generate a plain text .log file for a given source IP address
    try:
        # Regex to match records with the specified source IP address (SRC)
        regex = f'SRC={ip_address}'
        
        # Use filter_log_by_regex to get the relevant records
        matching_records = filter_log_by_regex(log_file, regex, ignore_case=True)[1]
        
        if matching_records:
            # Create the filename by replacing periods with underscores in the IP address
            filename = f'source_ip_{ip_address.replace(".", "_")}.log'
            
            # Open the file in write mode and save the records
            with open(filename, 'w') as output_file:
                for record in matching_records:
                    output_file.write(f"{record}\n")
            
            print(f"File generated: {filename}")
        else:
            print(f"No records found for source IP {ip_address}.")
    
    except Exception as e:
        print(f"Error while generating source IP log: {e}")

# Call the function in main() (you can adjust this based on what IP you want to filter by)
def main():
    log_file = get_log_file_path_from_cmd_line()
    
    # Call the function to generate the log file for a specific source IP
    generate_source_ip_log(log_file, '220.195.35.40')

if __name__ == '__main__':
    main()