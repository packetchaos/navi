import csv
from .api_wrapper import request_data


def was_csv_export():
    # Crete a csv file object
    with open('was_granular_data.csv', mode='w') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
        # write our Header information first
        header_list = ["Scan Name", "APP", "Risk", "Plugin ID", "Plugin Name"]
        agent_writer.writerow(header_list)

        params = {"size": "1000"}
        # Grab all of the Scans
        data = request_data('GET', '/was/v2/scans', params=params)

        for scan_data in data['data']:
            csv_list = []
            was_scan_id = scan_data['scan_id']
            status = scan_data['status']

            # Ignore all scans that have not completed
            if status == 'completed':
                report = request_data('GET', '/was/v2/scans/' + was_scan_id + '/report')

                try:
                    name = report['config']['name']
                    target = report['config']['settings']['target']

                    for finding in report['findings']:
                        risk = finding['risk_factor']
                        # ignore info vulns
                        if risk != "info":
                            plugin_id = finding['plugin_id']
                            plugin_name = finding['name']

                            csv_list.append(name)
                            csv_list.append(target)
                            csv_list.append(risk)
                            csv_list.append(plugin_id)
                            csv_list.append(plugin_name)

                            agent_writer.writerow(csv_list)
                except TypeError:
                    pass
        print()
