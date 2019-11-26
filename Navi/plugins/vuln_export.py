import time
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection, create_table, drop_tables, insert_vulns


def vuln_export():
    # Set the payload to the maximum number of assets to be pulled at once
    thirty_days = time.time() - 2660000
    pay_load = {"num_assets": 5000, "filters": {"last_found": int(thirty_days)}}
    try:
        # request an export of the data
        export = request_data('POST', '/vulns/export', payload=pay_load)

        # grab the export UUID
        ex_uuid = export['export_uuid']
        print('Requesting Vulnerability Export with ID : ' + ex_uuid)

        # now check the status
        status = request_data('GET', '/vulns/export/' + ex_uuid + '/status')

        # status = get_data('/vulns/export/89ac18d9-d6bc-4cef-9615-2d138f1ff6d2/status')
        print("Status : " + str(status["status"]))

        # set a variable to True for our While loop
        not_ready = True

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(5)
                status = request_data('GET', '/vulns/export/' + ex_uuid + '/status')
                print("Status : " + str(status["status"]))

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                not_ready = False

            # Tell the user an error occured
            if status['status'] == 'ERROR':
                print("Error occurred")



        #Crete a new connection to our database
        database = r"navi.db"
        conn = new_db_connection(database)
        drop_tables(conn, 'vulns')
        create_vuln_table = """CREATE TABLE IF NOT EXISTS vulns (
                            navi_id integer PRIMARY KEY,
                            asset_ip text, 
                            asset_uuid text, 
                            asset_hostname text, 
                            first_found text, 
                            last_found text, 
                            output text, 
                            plugin_id text, 
                            plugin_name text, 
                            plugin_family text, 
                            port text, 
                            protocol text, 
                            severity text, 
                            scan_completed text, 
                            scan_started text, 
                            scan_uuid text, 
                            schedule_id text, 
                            state text
                            );"""
        create_table(conn, create_vuln_table)

        with conn:
            navi_id = 0
            # loop through all of the chunks
            for chunk in status['chunks_available']:
                print("Parsing Chunk {} ...Finished".format(chunk+1))

                chunk_data = request_data('GET', '/vulns/export/' + ex_uuid + '/chunks/' + str(chunk+1))
                #print(chunk_data)
                for vulns in chunk_data:
                    #create a blank list to append asset details
                    list = []
                    navi_id = navi_id + 1
                    #Try block to ignore assets without IPs
                    try:
                        list.append(navi_id)
                        try:
                            ipv4 = vulns['asset']['ipv4']
                            list.append(ipv4)
                        except:
                            list.append(" ")

                        try:
                            asset_uuid = vulns['asset']['uuid']
                            list.append(asset_uuid)
                        except:
                            list.append(" ")

                        try:
                            hostname = vulns['asset']['hostname']
                            list.append(hostname)
                        except:
                            list.append(" ")

                        try:
                            first_found = vulns['first_found']
                            list.append(first_found)
                        except:
                            list.append(" ")

                        try:
                            last_found = vulns['last_found']
                            list.append(last_found)
                        except:
                            list.append(" ")

                        try:
                            output = vulns['output']
                            list.append(output)
                        except:
                            list.append(" ")

                        try:
                            plugin_id = vulns['plugin']['id']
                            list.append(plugin_id)
                        except:
                            list.append(" ")

                        try:
                            plugin_name = vulns['plugin']['name']
                            list.append(plugin_name)
                        except:
                            list.append(" ")

                        try:
                            plugin_family = vulns['plugin']['family']
                            list.append(plugin_family)
                        except:
                            list.append(" ")
                        try:
                            port = vulns['port']['port']
                            list.append(port)
                        except:
                            list.append(" ")
                        try:
                            protocol = vulns['port']['protocol']
                            list.append(protocol)
                        except:
                            list.append(" ")

                        try:
                            severity = vulns['severity']
                            list.append(severity)
                        except:
                            list.append(" ")
                        try:
                            scan_completed = vulns['scan']['completed_at']
                            list.append(scan_completed)
                        except:
                            list.append(" ")

                        try:
                            scan_started = vulns['scan']['started_at']
                            list.append(scan_started)
                        except:
                            list.append(" ")

                        try:
                            scan_uuid = vulns['scan']['uuid']
                            list.append(scan_uuid)
                        except:
                            list.append(" ")

                        try:
                            schedule_id = vulns['scan']['schedule_id']
                            list.append(schedule_id)
                        except:
                            list.append(" ")

                        try:
                            state = vulns['state']
                            list.append(state)
                        except:
                            list.append(" ")
                        try:
                            insert_vulns(conn, list)
                        except Error as e:
                            print(e)

                    except:
                        print("skipped one")
                        pass
    except KeyError:
        print("Well this is a bummer; you don't have permissions to download Asset data :( ")
