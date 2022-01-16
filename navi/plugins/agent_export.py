import csv
import time
from .api_wrapper import tenb_connection

tio = tenb_connection()


def agent_export():

    with open('agent_data.csv', mode='w', encoding='utf-8') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        header_list = ["Agent Name", "IP Address", "Platform", "Last connected", "Last scanned", "Status", "Plugin Feed ID"]
        agent_writer.writerow(header_list)

        try:
            for agent in tio.agents.list(limit=5000):

                try:
                    name = agent['name']
                    ip = agent['ip']
                    platform = agent['platform']
                except KeyError:
                    name = "Unknown"
                    ip = "Unknown"
                    platform = "Unknown"

                try:
                    plugin_feed = agent['plugin_feed_id']
                except KeyError:
                    plugin_feed = "Plugins Not updated"

                try:
                    last_connect = agent['last_connect']
                    connect_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(last_connect))
                except KeyError:
                    connect_time = "Unknown"

                try:
                    last_scanned = agent['last_scanned']
                    scanned_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(last_scanned))
                except KeyError:
                    scanned_time = "Not Yet Scanned"

                status = agent['status']
                agent_writer.writerow([name, ip, platform, connect_time, scanned_time, status, plugin_feed])
        except AttributeError:
            print("\nCheck your permissions or your API keys\n")
    return
