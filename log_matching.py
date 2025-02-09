'''log_matching.py - Module to help analyze a log file using regular expressions.
COMP 593 Scripting Applications - Winter 2025 (Week 5)
Louis Bertrand <louis.bertrand@flemingcollege.ca>

Usage: Import this module into your main program

### STUDENTS: PLEASE ADD THE STANDARD ACADEMIC INTEGRITY STATEMENT.###
# This program is strictly my own work. Any material beyond course learning
# materials that is taken from the Web or other sources is properly cited,
# giving credit to the original author(s).

'''

import re
import csv

def filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    # List of lines to be returned
    filtered_records = []  # start empty list
    filtered_groups = []  # start empty list of match groups

    # Set the regex search flag for case sensitivity
    # Ref: https://docs.python.org/3/library/re.html#re.IGNORECASE
    if ignore_case:
        search_flags = re.IGNORECASE
        sensitive = "ignoring case"  # info string for printing (see below)
    else:
        search_flags = 0
        sensitive = "case sensitive"  # info string for printing (see below)

    # Iterate the log file line by line
    with open(log_file, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            if match:
                # Add lines that match to list of filtered records
                # And strip the \n from the end of the line before saving
                filtered_records.append(record.strip())
                if match.lastindex != 0:
                    filtered_groups.append(match.groups())

    # Print all records, if enabled
    if print_records:
        for rec in filtered_records:
            print(rec)

    # Print summary of results, if enabled
    if print_summary:
        print(f'The log file contains {len(filtered_records)} records, {sensitive}, matching regex:\n  r"{regex}"')

    return (filtered_records, filtered_groups)

log_entry = "Jan 29 13:05:11 myth kernel: SFW2-INext-ACC-TCP IN=ppp0 OUT= MAC= SRC=220.195.35.40 DST=216.58.112.55 LEN=60 TOS=0x00 PREC=0x00 TTL=40 ID=9325 DF PROTO=TCP SPT=58989 DPT=22 WINDOW=5840 RES=0x00 SYN URGP=0 OPT (020405780402080A0265BA120000000001030300)"

regex = r'^[A-Za-z]{3}\s{1,2}\d{1,2}\s{1}\d{2}:\d{2}:\d{2}\s\w+\s(kernel):\sSFW2-INext-ACC-TCP\sIN=(\S+)\sOUT=(\S+)\sMAC=(\S+)\sSRC=(\S+)\sDST=(\S+)\sLEN=(\d+)\sTOS=\S+\sPREC=\S+\sTTL=(\d+)\sID=(\d+)\sDF\sPROTO=(\S+)\sSPT=(\d+)\sDPT=(\d+)\sWINDOW=(\d+)\sRES=\S+\sSYN\sURGP=(\d+)\sOPT=\S+$'

match = re.match(regex, log_entry)

if match:
    print("Match found!")
    # Capture the various fields from the log entry
    interface_in = match.group(1)
    interface_out = match.group(2)
    mac_address = match.group(3)
    src_ip = match.group(4)
    dst_ip = match.group(5)
    packet_length = match.group(6)
    ttl = match.group(7)
    id_field = match.group(8)
    protocol = match.group(9)
    src_port = match.group(10)
    dst_port = match.group(11)
    window_size = match.group(12)
    urgp = match.group(13)
    
    print(f"Input Interface: {interface_in}")
    print(f"Output Interface: {interface_out}")
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Source Port: {src_port}")
    print(f"Destination Port: {dst_port}")
else:
    print("No match.")


if __name__ == "__main__":
    print("Please import this file as a module to access its content.")