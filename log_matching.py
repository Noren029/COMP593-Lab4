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

if __name__ == "__main__":
    print("Please import this file as a module to access its content.")