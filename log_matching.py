'''log_matching.py - Module to help analyze a log file using regular expressions.
COMP 593 Scripting Applications - Winter 2025 (Week 5)
Louis Bertrand <louis.bertrand@flemingcollege.ca>

Usage: Import this module into your main program

### STUDENTS: PLEASE ADD THE STANDARD ACADEMIC INTEGRITY STATEMENT.###
# This program is strictly my own work. Any material beyond course learning
# materials that is taken from the Web or other sources is properly cited,
# giving credit to the original author(s).

'''

import sys
import os
import re


def get_log_file_path_from_cmd_line():
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        if os.path.isfile(filename):
            return os.path.abspath(filename)
        else:
            print("Not a file")
            exit(0)
    else:
        print("Insufficient arguments, please include filename")
        exit(0)
    return


def filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False):
    '''Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    '''
    filtered_records = []
    filtered_groups = []

    if ignore_case:
        search_flags = re.IGNORECASE
        sensitive = "case insensitive"
    else:
        search_flags = 0
        sensitive = "case sensitive"

    with open(log_file, 'r') as file:
        for record in file:
            match = re.search(regex, record, search_flags)
            if match:
                filtered_records.append(record.strip())
                if match.lastindex != 0:
                    filtered_groups.append(match.groups())

    if print_records:
        for rec in filtered_records:
            print(rec)

    if print_summary:
        print(f'The log files contains {len(filtered_records)} records, that are {sensitive}, matching regex:\n\r"{regex}"')
    
    return (filtered_records, filtered_groups)