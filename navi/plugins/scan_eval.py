import click
from .database import db_query, insert_scan_data, new_db_connection
from .dbconfig import create_scan_data_table
from .api_wrapper import tenb_connection
import csv

tio = tenb_connection()


def average_by_policy(name, scan_info):
    # Print the Category to the Screen ( Scanner, Policy, Scan Name)
    with open('{}.csv'.format(name), mode='w', encoding='utf-8', newline="") as my_file:
        average_writer = csv.writer(my_file, delimiter=',', quotechar='"')
        click.echo("\n{:100s} {:25s} {:10}".format(name, "AVG Minutes Per/Asset", "Total Assets"))
        click.echo("-" * 20)
        header = ["Scan Name", "Avg Minutes per/asset", "Total Assets"]
        average_writer.writerow(header)

        # Cycle through each category
        for scan in scan_info.items():

            # data is in a list [asset_uuid, mins] We need the length of the total mins found
            length = len(scan[1])

            # Reset the total per Category Item - Specific Scan ID, Scanner, Policy ID
            total = 0.0

            # Cycle through each asset record
            for assets in scan[1].values():
                # Gather a total
                try:
                    total = float(assets) + float(total)
                except TypeError:
                    print(total, assets)

            # After calculating the total, lets get an average
            average = total / length

            # Print results to the screen
            click.echo("\n{:100s} {:25d} {:10d}".format(scan[0], int(average), length))
            averages = [str(scan[0]), average, length]
            average_writer.writerow(averages)
        click.echo("-" * 150)


def show_stats():

    scan_data = db_query("select asset_uuid, scan_policy, scanner_ip, scan_name, scan_minutes from scan_data;")

    # Organize Data by Scan Policy
    scan_policy_dict = {}
    scanner_dict = {}
    scan_name_dict = {}
    # If the category is not in the new dict, add it; else update it.
    for vulns in scan_data:

        scan_policy = vulns[1]
        scanner_ip = vulns[2]
        scan_name = vulns[3]
        minutes = vulns[4]

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


def evaluate_scans():
    create_scan_data_table()
    click.echo("*" * 100)
    click.echo("\nThis command uses the 19506 plugin data found in the navi.db\n"
               "Run a navi update command to refresh the database.\n\nThis will take some time.\n")
    click.echo("*" * 100)
    # Pull all 19506 Plugins from the DB
    plugin_data = db_query("select asset_uuid, output from vulns where plugin_id='19506';")

    # Set some dicts for organizing Data
    click.echo("Evaluating multiple scans on {} assets".format(len(plugin_data)))
    scanner_list = []

    database = r"navi.db"
    scan_conn = new_db_connection(database)
    with scan_conn:
        for vulns in plugin_data:
            plugin_dict = {}

            # Output is the second item in the tuple from the DB
            plugin_output = vulns[1]

            # split the output by return
            parsed_output = plugin_output.split("\n")

            for info_line in parsed_output:
                try:
                    new_split = info_line.split(" : ")
                    plugin_dict[new_split[0]] = new_split[1]

                except:
                    pass
            try:
                intial_seconds = plugin_dict['Scan duration']
                try:
                    seconds = int(intial_seconds[:-3])
                    minutes = seconds / 60
                except ValueError:
                    minutes = 0

                try:
                    scan_name = plugin_dict['Scan name']
                except KeyError:
                    scan_name = "none"
                try:
                    scan_policy = plugin_dict['Scan policy used']
                except KeyError:
                    scan_policy = "none"
                try:
                    scanner_ip = plugin_dict['Scanner IP']
                    # Enumerate all scanners for per/scanner stats
                    if scanner_ip not in scanner_list:
                        scanner_list.append(scanner_ip)
                except KeyError:
                    scanner_ip = "none"
                try:
                    max_hosts = plugin_dict['Max hosts']
                except KeyError:
                    max_hosts = "none"
                try:
                    max_checks = plugin_dict['Max checks']
                except KeyError:
                    max_checks = "none"

                # Grabbing the start time from the plugin
                try:
                    start_time = plugin_dict['Scan Start Date']
                except KeyError:
                    start_time = "none"
                try:
                    rtt = plugin_dict['Ping RTT']
                except KeyError:
                    rtt = "none"

                parsed_data_organized = [vulns[0], scan_name, scan_policy, scanner_ip,
                                         start_time, max_checks, max_hosts, minutes, rtt]

                insert_scan_data(scan_conn, parsed_data_organized)

            except (IndexError, KeyError):
                # This error occurs when an old scanner is used.
                # the 19506 plugin filled with an error indicating the need for an upgrade
                pass


    show_stats()


