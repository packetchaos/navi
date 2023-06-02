import click
from csv import DictReader
from .database import db_query
from .api_wrapper import request_data, tenb_connection
import csv
import datetime
import time, pprint


tio = tenb_connection()


def grab_hop_count(uuid):
    # grab the output of 10287 - Trace Route
    hop_count_data = db_query("select output from vulns where asset_uuid='{}' and plugin_id='10287';".format(uuid))

    # Send the raw data back
    return hop_count_data


def parse_19506_from_file(filename, scanid, histid):
    # Set Total Vars
    total_assets_scanned_list = []
    reported_scan_duration = None
    total_reported_scan_duration = None

    # Let's get the scan time with scan processing
    scan_history = request_data("GET", "/scans/{}/history".format(scanid))

    for hist in scan_history['history']:
        if not hist['is_archived']:
            if str(hist['id']) == str(histid):
                reported_scan_start = hist['time_start']
                reported_scan_end = hist['time_end']
                total_reported_scan_duration = reported_scan_end - reported_scan_start

                # Simple Delta from Tenable.io reported Scan times
                reported_scan_duration = str(datetime.timedelta(seconds=total_reported_scan_duration))

    # Open the file and parse the 19506 plugin
    with open(filename) as fobj:
        scan_name = "No Scan"
        scan_policy = "No Policy"
        scanner_ip = "No Scanner"
        scanner_list = []
        max_hosts = " "
        max_checks = ""
        asset_average_scantime = 0
        start_scan_timestamp_list = []
        timestamp_plus_duration_list = []
        assets_skipped = 0

        plugin_dict = {}

        for row in DictReader(fobj):
            plugin_output = row['Plugin Output']
            asset_uuid = row['Asset UUID']

            # split the output by return
            parsed_output = plugin_output.split("\n")

            # put everything but warnings into a dictionary
            for info_line in parsed_output:

                try:
                    new_split = info_line.split(" : ")
                    plugin_dict[new_split[0]] = new_split[1]

                except:
                    # Skip warnings
                    pass

            try:
                # Split at the colon to grab the numerical value
                intial_seconds = plugin_dict['Scan duration']

                # For an unknown reason, the scanner will print unknown for some assets leaving no way to calculate the time.
                if intial_seconds != 'unknown':

                    try:
                        # split to remove "secs"
                        number = intial_seconds.split(" ")

                        # grab the number for our minute calculation
                        final_number = number[0]

                        # Numerical value in seconds parsed from the plugin
                        seconds = int(final_number)

                        # Grab data pair and split it at the colon and grab the values
                        scan_name = plugin_dict['Scan name']
                        scan_policy = plugin_dict['Scan policy used']
                        scanner_ip = plugin_dict['Scanner IP']
                        # Enumerate all scanners for per/scanner stats
                        if scanner_ip not in scanner_list:
                            scanner_list.append(scanner_ip)
                        max_hosts = plugin_dict['Max hosts']
                        max_checks = plugin_dict['Max checks']
                        # Grabbing the start time from the plugin
                        scan_time = plugin_dict['Scan Start Date']

                        # Some timezone abbreviations are not parseable with strptime.
                        # removing the timezone for those we can't parse
                        try:
                            # Set the pattern to convert into epoch
                            pattern = '%Y/%m/%d %H:%M %z'
                            # Convert to Epoch
                            plugin_scan_time_epoch = int(time.mktime(time.strptime(scan_time, pattern)))

                        except ValueError:

                            # timezone couldn't be used. lets remove it and calculate what we can
                            pattern = '%Y/%m/%d %H:%M'
                            # Split the time to remove the timezone 2-6 chars
                            time_less_timezone = scan_time.split(" ")
                            # merge the data and time for calculation
                            new_time = "{} {}".format(time_less_timezone[0], time_less_timezone[1])
                            # Convert to Epoch
                            plugin_scan_time_epoch = int(time.mktime(time.strptime(new_time, pattern)))

                        # Export time pattern
                        new_pattern = '%Y-%m-%dT%H:%M:%S'

                        # Add to list to calculate the first asset scanned
                        start_scan_timestamp_list.append(plugin_scan_time_epoch)

                        # Add epoch and seconds to get end time.  This will be used to find the last asset scanned
                        timestamp_plus_duration_list.append(plugin_scan_time_epoch + seconds)

                        pltfm_start = row['Host Start'].split(".")[0]
                        pltfm_end = row['Host End'].split(".")[0]

                        new_start = time.mktime(time.strptime(pltfm_start, new_pattern))
                        new_end = time.mktime(time.strptime(pltfm_end, new_pattern))

                        # Platform End time in epoch minus the start time epoch
                        total_duration = new_end - new_start

                        # Total duration minus the length of the scan
                        indexing_time = total_duration - seconds

                        # All assets and 19506 seconds in a tuple
                        total_assets_scanned_list.append((asset_uuid, row['Host Start'], scan_time, seconds, indexing_time, total_duration, row['Host End'], row['IP Address']))

                        # pprint.pprint(total_assets_scanned_list)

                    except IndexError:
                        # This error occurs when an old scanner is used.
                        # the 19506 plugin filled with an error indicating the need for an upgrade
                        assets_skipped += 1
                        pass
                else:
                    # Print plugin output to identify an unknown plugin structure/response
                    click.echo(plugin_output)
            except KeyError as E:
                # If there is no scan duration, skip the asset.
                assets_skipped += 1
                pass
        # calculate the total for AVG calc
        total = 0
        index_total = 0
        for assets_scanned in total_assets_scanned_list:
            total += assets_scanned[3]
            index_total += assets_scanned[4]

        try:
            # Avg scan time per asset
            asset_average_scantime = total / len(total_assets_scanned_list)

            asset_average_indextime = index_total / len(total_assets_scanned_list)

            # total Scan time is: the oldest (scan_date in 19506 + scan duration in 19506) minus the earliest scan date in 19506
            total_calculated_scan_duration = (max(timestamp_plus_duration_list) - min(start_scan_timestamp_list))

            # Processing time therefore is the reported duration - the total scan duration
            processing = total_reported_scan_duration - total_calculated_scan_duration

            longest_scanned = max(total_assets_scanned_list, key=lambda uuid: uuid[3])
            shortest_scanned = min(total_assets_scanned_list, key=lambda uuid: uuid[3])

            longest_index = max(total_assets_scanned_list, key=lambda uuid: uuid[4])
            shortest_index = min(total_assets_scanned_list, key=lambda uuid: uuid[4])

            click.echo("*" * 100)
            click.echo("This data is derived from the 19506 plugins found in the {}"
                       "\nThe start time stamp(s) and the duration(s) were used to calculate the total scan time(s)\n"
                       "For manual examination of the details please check out the the file: {}-parsing.csv".format(filename, scanid))
            click.echo("*" * 100)

            click.echo("\nScan Name: {}".format(scan_name))
            click.echo("Scanner Policy: {}".format(scan_policy))

            # We can't count cloud scanners; so let's not try
            if "tenable.io Scanner" in scanner_list:
                click.echo("\nScanned Using Tenable Cloud Scanners".format(len(scanner_list)))
            else:
                click.echo("\nTotal Scanners Used: {}".format(len(scanner_list)))

                for scanner in scanner_list:
                    click.echo("Scanner IP: {}".format(scanner))

            click.echo("\nMax Hosts: {}".format(max_hosts))
            click.echo("Max Checks: {}\n".format(max_checks))
            click.echo("{} {}".format("Total Assets scanned: ", len(total_assets_scanned_list)))
            click.echo("{} {}\n".format("Number of Assets skipped", assets_skipped))

            click.echo("{:40} {:10} {}".format("Scan Stats", "H: M: S", "Asset"))
            click.echo("-" * 60)
            click.echo("{:40} {:10}".format("Total Reported Scan Duration:", reported_scan_duration))
            click.echo("{:40} {:10}".format("Total T.io Processing Time:", str(datetime.timedelta(seconds=processing))))
            click.echo("{:40} {:10}\n".format("Actual Scan Duration: ", str(datetime.timedelta(seconds=total_calculated_scan_duration))))
            click.echo("Asset Stats")
            click.echo("-" * 40)
            click.echo("{:40} {:10} {}".format("Longest Asset Duration: ", str(datetime.timedelta(seconds=longest_scanned[3])), longest_scanned[0]))
            click.echo("{:40} {:10} {}".format("Shortest Asset Duration: ", str(datetime.timedelta(seconds=shortest_scanned[3])), shortest_scanned[0]))
            click.echo("{:40} {:10} {}".format("Longest Asset Index: ", str(datetime.timedelta(seconds=longest_index[4])), longest_index[0]))
            click.echo("{:40} {:10} {}\n".format("Shortest Asset Index: ", str(datetime.timedelta(seconds=shortest_index[4])), shortest_index[0]))
            click.echo("Averages Stats")
            click.echo("-" * 40)
            click.echo("{:40} {}".format("Average scan duration per Asset:", str(datetime.timedelta(seconds=asset_average_scantime))))
            click.echo("{:40} {}\n".format("Average processing per Asset:", str(datetime.timedelta(seconds=asset_average_indextime))))

            click.echo("\nFirst asset scanned started at: {}".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(min(start_scan_timestamp_list)))))
            click.echo("Last asset finished scanning at: {}\n\n".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(max(timestamp_plus_duration_list)))))

        except ZeroDivisionError:
            click.echo("\nScan history had No data.\n")

    with open("13-parsing.csv", mode='w', encoding='utf-8', newline="") as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
        header = ["UUID", "Platform_Start", "19506_scantime", "19506_duration","Indexing duration", "Total_duration",  "Platform_end", "IP Address"]

        agent_writer.writerow(header)
        # Loop through each asset
        for assets in total_assets_scanned_list:
            agent_writer.writerow(assets)


def get_last_history_id(scanid):
    data = request_data("GET", "/scans/{}/history".format(scanid))
    for scans in data['history']:
        if not scans['is_archived']:
            if scans['status'] == 'completed':
                return scans['id']
            else:
                click.echo("\nNo completed Scan to evaluate\n")
                exit()
        else:
            click.echo("\nNo completed Scan to evaluate\n")
            exit()


def download_csv_by_plugin_id(scan_id, hist_id):
    filename = f'{scan_id}-report.csv'
    click.echo("\nDownloading scan {} details into a csv called {} for "
               "parsing and manual auditing\n".format(scan_id, filename))

    # Stream the report to disk
    with open(filename, 'wb') as fobj:
        tio.scans.export(scan_id, ('plugin.id', 'eq', '19506'),
                         format='csv', fobj=fobj, history_id=hist_id)
    # Now parse the data
    parse_19506_from_file(filename, scan_id, hist_id)


def evaluate_a_scan(scanid, histid):

    if scanid:
        if histid:
            # use the scan id and hist id to download and parse
            download_csv_by_plugin_id(scanid, histid)
        else:
            # grab the last usable histid
            historyid = get_last_history_id(scanid)
            # download and parse
            download_csv_by_plugin_id(scanid, historyid)
    else:
        # Since no scanid was provided we assume the user wants stats on all scans
        click.echo("*" * 100)
        click.echo("\nThis command uses the 19506 plugin data found in the navi.db\n"
                   "Run a navi update command to refresh the database.\n")
        click.echo("*" * 100)
        # Pull all 19506 Plugins from the DB
        plugin_data = db_query("select asset_uuid, output from vulns where plugin_id='19506';")

        # Set some dicts for organizing Data
        scan_policy_dict = {}
        scanner_dict = {}
        scan_name_dict = {}

        # Open a CSV for export
        with open('evaluate.csv', mode='w', encoding='utf-8', newline="") as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            header_list = ["asset uuid", "Scan Name", "Scan Policy", "Scanner IP", "Scan Time", "Max Checks", "Max Hosts", "Minutes", "RTT", "Hop Count"]

            # Write the header to the csv
            agent_writer.writerow(header_list)

            # This function is used to parse the data
            # Getting the length of the Category and using it to get the average
            def average_by_policy(name, scan_info):
                # Print the Category to the Screen ( Scanner, Policy, Scan Name)
                click.echo("\n{:100s} {:25s} {:10}".format(name, "AVG Minutes Per/Asset", "Total Assets"))
                click.echo("-" * 20)

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
                    click.echo("\n{:100s} {:25d} {:10d}".format(scan[0], int(average), length))

                click.echo("-" * 150)

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

                try:
                    # split to remove "secs"
                    number = seconds[1].split(" ")
                except:
                    # No plugin Data for this asset
                    pass

                # grab the number for our minute calculation
                final_number = number[0]

                if final_number != 'unknown':
                    try:
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
                    except IndexError:
                        # This error occurs when an old scanner is used.
                        # the 19506 plugin filled with an error indicating the need for an upgrade
                        pass

            average_by_policy("Policies", scan_policy_dict)

            average_by_policy("Scanners", scanner_dict)

            average_by_policy("Scan Name", scan_name_dict)

