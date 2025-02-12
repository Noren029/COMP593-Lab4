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
import re
import logging

def main():
    log_file = get_log_file_path_from_cmd_line()

    regex =r'sshd'
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)

    regex =r'invalid user'
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)

    regex =r'invalid user.*220.195.35.40' 
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)

    regex =r'pam'
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)

    regex =r'error'
    filter_log_by_regex(log_file, regex, ignore_case=True,print_summary =True, print_records=True)


    #step 8 
    port_traffic = tally_port_traffic(log_file)

    #step 10
    for port, count in port_traffic.items():
         if (count >=100 ):
              print(f'Port {port} has traffic greater than or equal to 100, it is {count}')

# TODO: Step 8
def tally_port_traffic(log_file):
    port_traffic = {}

    with open(log_file, 'r')as file:
         for record in file:
              match = re.search(r'DPT=([^ ]*)', record)
              if match:
                   port = match.group(1)
                   port_traffic[port]=port_traffic.get(port,0)+1

    return port_traffic

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):

    regex = r'^(.{6}) (.*) myth.*SRC=(.*?) DST=(.*?) .*SPT(.*?) '+ f'DPT=({port_number})'
    traffic_records = filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False)[1]

    if traffic_records:
         traffic_df = pd.DataFrame(traffic_records, columns=['Date', 'Time', 'Source IP Address', 'Source Port', 'Destination Port'])
         traffic_df.to_csv(f'destination_port_{port_number}_report.csv',index=False)
         print(f"CSV file 'destination_port_{port_number}_report.csv' generated successfully.")
    else:
         print(f"No records found for port {port_number}.")

    return

# TODO: Step 11
def generate_invalid_user_report(log_file):

    regex = r'^(.{6}) (.*) myth sshd.{6}.: Invalid user anonymous from 220.195.35.40)  '
    invalid_user = filter_log_by_regex(log_file,regex)[2]

    invalid_df = pd.DataFrame(invalid_user)
    invalid_header = ('Date', 'Time', 'Username', 'IP Address'  )

    invalid_df.to_csv(f'Invalid_user_report.csv',header=invalid_header, index=False)


    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):

    regex = r'^(.{6}) (.*) myth.*SRC=(.*?) DST=(.*?) .*SPT(.*?) '+ f'DPT=({ip_address})'
    source_ip = filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False)[3]

    if source_ip:
         source_df = pd.DataFrame(source_ip, columns=['Date', 'Time', 'Source IP Address', 'Source Port', 'Destination Port'])
         source_df.to_csv(f'source_ip{ip_address}_log.csv',index=False)
         print(f"CSV file 'source_ip{ip_address}_log.csv' generated successfully.")
    else:
         print(f"No records found for port {ip_address}.")

    return

if __name__ == '__main__':
        main()