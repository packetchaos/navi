import csv
from sqlite3 import Error
from .api_wrapper import request_data


def add_helper(file, source):
    try:

        with open(file, 'r', newline='') as new_file:
            add_assets = csv.reader(new_file)

            for row in add_assets:
                asset = {}
                ipv4 = []
                macs = []
                fqdns = []
                hostnames = []

                ipv4.append((row[0]))
                asset["ip_address"] = ipv4

                macs.append(row[1])
                asset["mac_address"] = macs

                hostnames.append(row[2])
                asset["hostname"] = hostnames

                fqdns.append(row[3])
                asset["fqdn"] = fqdns

                # create Payload
                payload = {"assets": [asset], "source": source}

                print("Added the following Data : \n")
                print(payload)
                print()

                # request Import Job
                data = request_data('POST', '/import/assets', payload=payload)
                print("Your Import ID is : ", data['asset_import_job_uuid'])
    except Error as e:
        print(e)
