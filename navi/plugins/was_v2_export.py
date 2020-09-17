import csv
import click
from .api_wrapper import request_data


def was_export():
    # Crete a csv file object
    with open('was_summary_data.csv', mode='w') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
        # write our Header information first
        header_list = ["Scan Name", "Target", "High", "Medium", "Low", "Scan Start", "Scan Finish", "Note Title", "Note Message"]
        agent_writer.writerow(header_list)

        params = {"size": "1000"}
        # Grab all of the Scans
        data = request_data('GET', '/was/v2/scans', params=params)
        print(data)
        for scan_data in data['data']:
            csv_list = []
            was_scan_id = scan_data['scan_id']
            status = scan_data['status']
            start = scan_data['started_at']
            finish = scan_data['finalized_at']

            # Ignore all scans that have not completed
            if status == 'completed':
                report = request_data('GET', '/was/v2/scans/' + was_scan_id + '/report')
                high = []
                medium = []
                low = []
                try:
                    name = report['config']['name']
                    try:
                        target = report['scan']['target']
                    except KeyError:
                        target = report['config']['settings']['target']
                    try:
                        title = report['notes'][0]['title']
                        message = report['notes'][0]['message']
                    except IndexError:
                        # There may not be any Notes set the vars to ""
                        title = ""
                        message = ""

                    for finding in report['findings']:
                        risk = finding['risk_factor']
                        plugin_id = finding['plugin_id']
                        if risk == 'high':
                            high.append(plugin_id)
                        elif risk == 'medium':
                            medium.append(plugin_id)
                        elif risk == 'low':
                            low.append(plugin_id)

                    csv_list.append(name)
                    csv_list.append(target)
                    csv_list.append(len(high))
                    csv_list.append(len(medium))
                    csv_list.append(len(low))
                    csv_list.append(start)
                    csv_list.append(finish)
                    csv_list.append(title)
                    csv_list.append(message)
                    agent_writer.writerow(csv_list)
                except TypeError as E:
                    print(E)
        click.echo()
