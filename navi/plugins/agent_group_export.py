import csv
import time
from .api_wrapper import request_data


def agent_group_export(group):

    data = request_data('GET', '/scanners/1/agent-groups')

    for group_info in data['groups']:
        group_name = group_info['name']

        if group_name == group:
            group_id = group_info['id']

            agent_data = request_data('GET', '/scanners/1/agent-groups/' + str(group_id) + '/agents')

            with open('agent_group_data.csv', mode='w') as csv_file:
                agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

                header_list = ["Agent Name", "IP Address", "Platform", "Last connected", "Last scanned", "Status", "Plugin Feed ID"]
                agent_writer.writerow(header_list)

                # cycle through the agents and display the useful information
                for agent in agent_data['agents']:
                    name = agent['name']
                    ip = agent['ip']
                    platform = agent['platform']
                    plugin_feed = agent['plugin_feed_id']

                    last_connect = agent['last_connect']
                    connect_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(last_connect))
                    try:
                        last_scanned = agent['last_scanned']
                        scanned_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(last_scanned))
                    except KeyError:
                        scanned_time = "Not Yet Scanned"
                    status = agent['status']

                    agent_writer.writerow([name, ip, platform, connect_time, scanned_time, status, plugin_feed])
    return
