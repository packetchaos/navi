import csv
import time
from .api_wrapper import request_data


def agent_export():
    data = request_data('GET', '/scanners')

    # get US cloud Scanner ID
    for scanner in range(len(data['scanners'])):
        if data['scanners'][scanner]['name'] == 'US Cloud Scanner':
            scan_id = data['scanners'][scanner]['id']
            querystring = {"limit": "5000"}
            # pull agent data from the US cloud Scanner
            agents = request_data('GET', '/scanners/' + str(scan_id) + '/agents', params=querystring)

            with open('agent_data.csv', mode='w') as csv_file:
                agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

                header_list = ["Agent Name", "IP Address", "Platform", "Last connected", "Last scanned", "Status", "Plugin Feed ID"]
                agent_writer.writerow(header_list)

                # cycle through the agents and display the useful information
                for a in agents['agents']:
                    name = a['name']
                    ip = a['ip']
                    platform = a['platform']
                    plugin_feed = a['plugin_feed_id']

                    last_connect = a['last_connect']
                    connect_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(last_connect))
                    try:
                        last_scanned = a['last_scanned']
                        scanned_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(last_scanned))
                    except KeyError:
                        scanned_time = "Not Yet Scanned"
                    status = a['status']

                    agent_writer.writerow([name, ip, platform, connect_time, scanned_time, status, plugin_feed])
    return
