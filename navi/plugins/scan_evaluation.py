import click
from .database import db_query
import pprint
import csv
# Grab all 19506 Data


def grab_hop_count(uuid):
    # grab the output of 10287 - Trace Route
    hop_count_data = db_query("select output from vulns where asset_uuid='{}' and plugin_id='10287';".format(uuid))

    # Send the raw data back
    return hop_count_data


@click.command(help="Evaluate Scan times")
def evaluate():

    # Pull all 19506 Plugins from the DB
    plugin_data = db_query("select asset_uuid, output from vulns where plugin_id='19506';")

    # Set some dicts for organizing Data
    scan_policy_dict = {}
    scanner_dict = {}
    scan_name_dict = {}

    # Open a CSV for export
    with open('evaluate.csv', mode='w') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        header_list = ["asset uuid", "Scan Name", "Scan Policy", "Scanner IP", "Scan Time", "Max Checks", "Max Hosts", "Minutes", "RTT", "Hop Count"]

        # Metics Header
        #header_list = ["Policy/Scanner/Scan", "Average per Asset in mins"]

        # Write the header to the csv
        agent_writer.writerow(header_list)

        # This function is used to parse the data
        # Getting the length of the Category and using it to get the average
        def average_by_policy(name, scan_info):
            # Print the Category to the Screen ( Scanner, Policy, Scan Name)
            print("\n{:100s} {:25s} {:10}".format(name, "AVG Minutes Per/Asset", "Total Assets"))
            print("-" * 20)

            # Write the category to the csv for delination
            #agent_writer.writerow([name])

            # Cycle through each category
            for scan in scan_info.items():

                # data is in a list [asset_uuid, mins] We need the length of the total mins found
                length = len(scan[1])

                # Reset the total per Category Item - Specific Scan ID, Scanner, Policy ID
                total = 0

                # Cycle through each asset record
                for assets in scan[1].values():
                    # Gather a total
                    total = assets + total

                # After calculating the total, lets get an average
                average = total/length

                # Print results to the screen
                print("\n{:100s} {:25d} {:10d}".format(scan[0], int(average), length))

                update = [scan[0], average]

                # Send the results as a list to the CSV
                #agent_writer.writerow(update)
            print("-" * 150)

        # Loop through each plugin 19506 and Parse data from it
        for vulns in plugin_data:

            # Output is the second item in the tuple from the DB
            plugin_output = vulns[1]

            # split the output by return
            parsed_output = plugin_output.split("\n")

            # grab the length so we can grab the seconds
            plugin_length = len(parsed_output)

            # grab the scan duration- second to the last variable
            duration = parsed_output[plugin_length - 2]

            # Split at the colon to grab the numerical value
            seconds = duration.split(" : ")

            # split to remove "secs"
            number = seconds[1].split(" ")

            # grab the number for our minute calculation
            final_number = number[0]

            if final_number != 'unknown':
                # convert seconds into minutes
                minutes = int(final_number) / 60

                # Grab data pair and split it at the colon and grab the values
                scan_name = parsed_output[9].split(" : ")[1]
                scan_policy = parsed_output[10].split(" : ")[1]
                scanner_ip = parsed_output[11].split(" : ")[1]
                scan_time = parsed_output[plugin_length - 3].split(" : ")[1]
                max_hosts = parsed_output[plugin_length- 8].split(" : ")[1]
                max_checks = parsed_output[plugin_length - 7].split(" : ")[1]

                if "no" not in parsed_output[14].split(" : ")[1]:
                    rtt = parsed_output[14].split(" : ")[1]
                else:
                    rtt = parsed_output[12].split(" : ")[1]

                try:
                    # Grab the last line in the Trace route Plugin output
                    # Split on the space and grab the numerical value.
                    hopcount = grab_hop_count(vulns[0])[0][-1].split(" ")[-1]
                except IndexError:
                    hopcount = "Unknown"

                parsed_data_organized = [vulns[0], scan_name, scan_policy, scanner_ip, scan_time, max_checks, max_hosts, minutes, rtt, hopcount]

                agent_writer.writerow(parsed_data_organized)

                # Organize Data by Scan Policy
                # If the category is not in the new dict, add it; else update it.
                if scan_policy not in scan_policy_dict:
                    scan_policy_dict[scan_policy] = {vulns[0]: minutes}
                else:
                    scan_policy_dict[scan_policy].update({vulns[0]: minutes})

                if scanner_ip not in scanner_dict:
                    scanner_dict[scanner_ip] = {vulns[0]: minutes}
                else:
                    scanner_dict[scanner_ip].update({vulns[0]: minutes})

                if scan_name not in scan_name_dict:
                    scan_name_dict[scan_name] = {vulns[0]: minutes}
                else:
                    scan_name_dict[scan_name].update({vulns[0]: minutes})

        average_by_policy("Policies", scan_policy_dict)

        average_by_policy("Scanners", scanner_dict)

        average_by_policy("Scan Name", scan_name_dict)
