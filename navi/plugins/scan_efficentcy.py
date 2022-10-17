import csv
import click
import datetime
import time
from csv import DictReader
from .api_wrapper import tenb_connection
import textwrap

tio = tenb_connection()


def parse_19506(plugin_output):
    """
            Parse 19506 output and return a list of data
    """
    # split the output by return
    parsed_output = plugin_output.split("\n")

    # grab the length so we can grab the seconds
    plugin_length = len(parsed_output)

    # grab the scan duration- second to the last variable
    duration = parsed_output[plugin_length - 2]

    # Split at the colon to grab the numerical value
    intial_seconds = duration.split(" : ")

    # split to remove "secs"
    number = intial_seconds[1].split(" ")

    # grab the number for our calculation
    final_number = number[0]

    # For an unknown reason, the scanner will print unknown for some assets leaving no way to calculate the time.
    if final_number != 'unknown':
        try:
            # Numerical value in seconds parsed from the plugin
            seconds = int(final_number)

            # Grab data pair and split it at the colon and grab the values
            scan_name = parsed_output[9].split(" : ")[1]
            scan_policy = parsed_output[10].split(" : ")[1]
            scanner_ip = parsed_output[11].split(" : ")[1]
            max_hosts = parsed_output[plugin_length - 8].split(" : ")[1]
            max_checks = parsed_output[plugin_length - 7].split(" : ")[1]

            # Grabbing the start time from the plugin
            start_time = parsed_output[plugin_length - 3].split(" : ")[1]
            output_list = [scan_name, scan_policy, scanner_ip, max_hosts, max_checks, start_time, seconds]

            return output_list
        except IndexError:
            return "fail"


def convert_start_date(start_time):
    # Some timezone abrivations are not parseable with strptime.
    # removing the timezone for those we can't parse
    try:
        # Set the pattern to convert into epoch
        pattern = '%Y/%m/%d %H:%M %Z'

        # Convert to Epoch
        start_time_epoch = int(time.mktime(time.strptime(start_time, pattern)))

    except ValueError:
        # timezone couldn't be used. lets remove it and calculate what we can
        pattern = '%Y/%m/%d %H:%M'

        # Split the time to remove the timezone 2-6 chars
        time_less_timezone = start_time.split(" ")

        # merge the data and time for calculation
        new_time = "{} {}".format(time_less_timezone[0], time_less_timezone[1])

        # Convert to Epoch
        start_time_epoch = int(time.mktime(time.strptime(new_time, pattern)))

    return start_time_epoch


def organize_19506_composite_data(filename):
    scanner_list = []
    total_assets_scanned_list = []
    start_scan_timestamp_list = []
    timestamp_plus_duration_list = []

    with open(filename) as fobj:

        for row in DictReader(fobj):
            plugin_output = row['Plugin Output']
            asset_uuid = row['Asset UUID']

            # Parse the plugin and accept the list
            plugin_list = parse_19506(plugin_output)

            if plugin_list != 'fail':
                seconds = plugin_list[6]

                scan_name = plugin_list[0]
                scan_policy = plugin_list[1]

                # There could be more than one scanner; create a list to store them all
                if plugin_list[2] not in scanner_list:
                    scanner_list.append(plugin_list[2])

                # Grabbing the start time from the plugin
                start_time_epoch = convert_start_date(plugin_list[5])

                # Add to list to calculate the first asset scanned
                start_scan_timestamp_list.append(start_time_epoch)

                # Add epoch and seconds to get end time.  This will be used to find the last asset scanned
                timestamp_plus_duration_list.append(start_time_epoch + seconds)

                # All assets and 19506 seconds in a tuple
                total_assets_scanned_list.append((asset_uuid, seconds))

                # calculate the total for AVG calc
            total = 0
            for secs in total_assets_scanned_list:
                total += secs[1]

    organize_composite_data = {"Scanner List": scanner_list, "Total Assets": total_assets_scanned_list,
                               "Start Scan List": start_scan_timestamp_list,
                               "Duration List": timestamp_plus_duration_list,
                               "Total": total,
                               "Scan Name": scan_name,
                               "Scan Policy": scan_policy}

    return organize_composite_data


def decorate_19506_data(filename):
    # Grab the composite data
    composite_data = organize_19506_composite_data(filename)

    # reassign the composite data for calculations
    total_assets_scanned_list = composite_data['Total Assets']

    scanner_list = composite_data["Scanner List"]

    start_scan_timestamp_list = composite_data["Start Scan List"]

    timestamp_plus_duration_list = composite_data["Duration List"]

    total = composite_data["Total"]

    scan_policy = composite_data["Scan Policy"]

    scan_name = composite_data["Scan Name"]

    try:

        # Avg scan time per asset
        asset_average_scantime = total / len(total_assets_scanned_list)

        # total Scan time is: the oldest (scan_date in 19506 + scan duration in 19506) minus the earliest scan date in 19506
        total_calculated_scan_duration = (max(timestamp_plus_duration_list) - min(start_scan_timestamp_list))

        # The asset that took the longest will be the biggest number
        longest_scanned = max(total_assets_scanned_list, key=lambda uuid: uuid[1])

        # The asset that took the shortest will be the smallest number
        shortest_scanned = min(total_assets_scanned_list, key=lambda uuid: uuid[1])

        # Instead of providing the UUID, provide the URL that points to the Asset details page
        short_asset_special_url = "https://cloud.tenable.com/tio/app.html#/assets-uw/hosts-assets/details/{}/findings?uw_asset_details_findings_nessus.st=severity.1".format(
            shortest_scanned[0])
        long_asset_special_url = "https://cloud.tenable.com/tio/app.html#/assets-uw/hosts-assets/details/{}/findings?uw_asset_details_findings_nessus.st=severity.1".format(
            longest_scanned[0])

        # collect the data in a list and return it
        trend_data = [str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(min(start_scan_timestamp_list)))),
                      str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(max(timestamp_plus_duration_list)))),
                      scan_policy, scanner_list, scan_name, len(total_assets_scanned_list),
                      str(datetime.timedelta(seconds=asset_average_scantime)),
                      str(datetime.timedelta(seconds=total_calculated_scan_duration)),
                      str(datetime.timedelta(seconds=int(shortest_scanned[1]))), short_asset_special_url,
                      str(datetime.timedelta(seconds=int(longest_scanned[1]))), long_asset_special_url]
        return trend_data, total_calculated_scan_duration

    except ZeroDivisionError:
        click.echo("\nScan history had No data.\n")


def download_csv_by_plugin_id(scan_id, hist_id):
    filename = f'{scan_id}-{hist_id}-report.csv'

    # Stream the report to disk
    with open(filename, 'wb') as fobj:
        tio.scans.export(scan_id, ('plugin.id', 'eq', '19506'),
                         format='csv', fobj=fobj, history_id=hist_id)

    return filename


def trend_by_scan_id(scanid):

    with open('Trending_report_scan_{}.csv'.format(scanid), mode='w', encoding='utf-8', newline="") as trend_file:
        trend_writer = csv.writer(trend_file, delimiter=',', quotechar='"')
        header = ["Scan URl", "Scan Start", "Last Asset Scanned", "Scan Policy", "Scanner IP", "Scan Name",
                  "Total Assets",
                  "Average Scan Duration", "Reported Time", "Indexing Time", "Scan Duration", "Shortest Asset time",
                  "Shortest Scanned Asset", "Longest Asset time", "longest Scanned Asset"]
        trend_writer.writerow(header)

        for hist in tio.scans.history(scanid):  # scan_hist['history']:
            if not hist['is_archived']:
                if hist['status'] == 'completed':
                    # Lets get the Reported Scan Duration
                    reported_scan_start = hist['time_start']
                    reported_scan_end = hist['time_end']
                    total_reported_scan_duration = reported_scan_end - reported_scan_start

                    # Simple Delta from Tenable.io reported Scan times
                    reported_scan_duration = str(datetime.timedelta(seconds=total_reported_scan_duration))

                    click.echo("\nDownloading scan {}, history {} details into a csv called {}-{}.csv for "
                               "parsing and manual auditing\n".format(scanid, hist['id'], scanid, hist['id']))

                    # Download the Scan data
                    scan_file_name = download_csv_by_plugin_id(scanid, hist['id'])

                    # Parse the downloaded file
                    scan_details, total_calculated_scan = decorate_19506_data(scan_file_name)

                    # Processing time therefore is the reported duration - the total scan duration
                    processing = total_reported_scan_duration - total_calculated_scan

                    # Constructing the scan URL for ease of use
                    scan_url = "https://cloud.tenable.com/tio/app.html#/assess/scans/vm-scans/folders/1/scan-details/{}/{}/" \
                               "by-plugin/vulnerability-details/19506/details".format(scanid, hist['scan_uuid'])

                    # Insert the reported duration and scan url
                    scan_details.insert(0, scan_url)
                    scan_details.insert(8, reported_scan_duration)
                    scan_details.insert(9, datetime.timedelta(seconds=processing))

                    # Write to File
                    trend_writer.writerow(scan_details)


def display_data(scanid):

    with open('Trending_report_scan_{}.csv'.format(scanid), mode='r', encoding='utf-8', newline="") as trend_file:
        click.echo()
        click.echo("*" * 100)
        click.echo("\nThis data is derived from the 19506 plugins found in the last 30 days of available scan history of scan {}"
                   "\nThe start time stamps and the durations were used to calculate the total scan times"
                   "\nThe file Trending_report_scan_{}.csv has all of the available data, including links to assets and scan history\n".format(scanid, scanid))
        click.echo("*" * 100)
        click.echo("\n{:20} {:25} {:10} {:20} {:20} {:20} {:20} {:25}".format("Scan Start", "Scanner IP(s)", "Assets", "Reported",
                                                                              "Indexing", "Duration", "Average",
                                                                              "Longest Asset time"))
        click.echo("-" * 150)

        for detail in DictReader(trend_file):
            click.echo("{:20} {:25} {:10} {:20} {:20} {:20} {:20} {:25}".format(str(detail["Scan Start"]), textwrap.shorten(str(detail["Scanner IP"]), width=25),
                                                                                str(detail["Total Assets"]), str(detail["Reported Time"]),
                                                                                str(detail["Indexing Time"]), str(detail["Scan Duration"]),
                                                                                detail["Average Scan Duration"], str(detail["Longest Asset time"])))

    click.echo()



