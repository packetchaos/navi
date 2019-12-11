import csv
from .api_wrapper import request_data


def webapp_export():

    # Crete a csv file object
    with open('webapp_data.csv', mode='w') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
        # write our Header information first
        header_list = ["Hostname", "Critical", "High", "Medium", "Low", "Scan Note"]
        agent_writer.writerow(header_list)

        data = request_data('GET', '/scans')
        # cycle through all of the scans and pull out the webapp scan IDs

        for scans in data['scans']:
            csv_list = []
            if scans['type'] == 'webapp':
                scan_details = request_data('GET', '/scans/'+str(scans['id']))
                try:
                    hostname = scan_details['hosts'][0]['hostname']
                except:
                    hostname = " "
                try:
                    message = scan_details['notes'][0]['message']
                except:
                    message = " "
                try:
                    critical = scan_details['hosts'][0]['critical']
                except:
                    critical = 0
                try:
                    high = scan_details['hosts'][0]['high']
                except:
                    high = 0
                try:
                    medium = scan_details['hosts'][0]['medium']
                except:
                    medium = 0
                try:
                    low = scan_details['hosts'][0]['low']
                except:
                    low = 0

                if message != "Job expired while pending status.":
                    csv_list.append(hostname)

                    csv_list.append(critical)
                    csv_list.append(high)
                    csv_list.append(medium)
                    csv_list.append(low)
                    csv_list.append(message)
                    agent_writer.writerow(csv_list)
