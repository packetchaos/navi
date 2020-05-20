import time
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection, drop_tables, insert_vulns
from .dbconfig import create_vulns_table


def vuln_export(days, ex_uuid):
    '''OLD CODE - NOT in Navi anylonger'''
    start = time.time()
    # Crete a new connection to our database
    database = r"navi.db"
    drop_conn = new_db_connection(database)

    # Right now we just drop the table.  Eventually I will actually update the database
    drop_tables(drop_conn, 'vulns')

    # Set the payload to the maximum number of assets to be pulled at once
    day = 86400
    new_limit = day * int(days)
    day_limit = time.time() - new_limit
    pay_load = {"num_assets": 500, "filters": {"last_found": int(day_limit)}}
    try:

        if ex_uuid == '0':
            # request an export of the data
            export = request_data('POST', '/vulns/export', payload=pay_load)

            # grab the export UUID
            ex_uuid = export['export_uuid']
            print('\nRequesting Vulnerability Export with ID : ' + ex_uuid)

            # set a variable to True for our While loop
            not_ready = True
        else:
            print("\nUsing your Export UUID\n")
            not_ready = True

        # now check the status
        status = request_data('GET', '/vulns/export/' + ex_uuid + '/status')

        # status = get_data('/vulns/export/89ac18d9-d6bc-4cef-9615-2d138f1ff6d2/status')
        print("Status : " + str(status["status"]))

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(15)
                status = request_data('GET', '/vulns/export/' + ex_uuid + '/status')
                print("Status : " + str(status["status"]))

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                ptime = time.time()
                print("\nProcessing Time took : " + str(ptime - start))
                not_ready = False

            # Tell the user an error occured
            if status['status'] == 'ERROR':
                print("Error occurred")

        create_vulns_table()
        # Open a fresh connection to import data

        navi_id = 0
        vuln_conn = new_db_connection(database)
        vuln_conn.execute('pragma journal_mode=wal;')
        with vuln_conn:
            # loop through all of the chunks
            for chunk in status['chunks_available']:
                print("\nParsing Chunk {} of {} ...Finished".format(chunk, status['total_chunks']))
                cstart = time.time()
                chunk_data = request_data(
                    'GET', '/vulns/export/' + ex_uuid + '/chunks/' + str(chunk))

                dbtime = time.time()
                print("This chunk took : " + str(dbtime - cstart) + " To Download")

                for vulns in chunk_data:
                    # create a blank list to append asset details
                    vuln_list = []
                    navi_id = navi_id + 1
                    # Try block to ignore assets without IPs
                    try:
                        vuln_list.append(navi_id)
                        try:
                            ipv4 = vulns['asset']['ipv4']
                            vuln_list.append(ipv4)
                        except IndexError:
                            vuln_list.append(" ")

                        try:
                            asset_uuid = vulns['asset']['uuid']
                            vuln_list.append(asset_uuid)
                        except IndexError:
                            vuln_list.append(" ")

                        try:
                            hostname = vulns['asset']['hostname']
                            vuln_list.append(hostname)
                        except IndexError:
                            vuln_list.append(" ")

                        try:
                            first_found = vulns['first_found']
                            vuln_list.append(first_found)
                        except IndexError:
                            vuln_list.append(" ")

                        try:
                            last_found = vulns['last_found']
                            vuln_list.append(last_found)
                        except IndexError:
                            vuln_list.append(" ")

                        try:
                            output = vulns['output']
                            vuln_list.append(output)
                        except KeyError:
                            vuln_list.append(" ")

                        try:
                            plugin_id = vulns['plugin']['id']
                            vuln_list.append(plugin_id)
                        except KeyError:
                            vuln_list.append(" ")

                        try:
                            plugin_name = vulns['plugin']['name']
                            vuln_list.append(plugin_name)
                        except KeyError:
                            vuln_list.append(" ")

                        try:
                            plugin_family = vulns['plugin']['family']
                            vuln_list.append(plugin_family)
                        except KeyError:
                            vuln_list.append(" ")
                        try:
                            port = vulns['port']['port']
                            vuln_list.append(port)
                        except KeyError:
                            vuln_list.append(" ")
                        try:
                            protocol = vulns['port']['protocol']
                            vuln_list.append(protocol)
                        except KeyError:
                            vuln_list.append(" ")

                        try:
                            severity = vulns['severity']
                            vuln_list.append(severity)
                        except KeyError:
                            vuln_list.append(" ")
                        try:
                            scan_completed = vulns['scan']['completed_at']
                            vuln_list.append(scan_completed)
                        except KeyError:
                            vuln_list.append(" ")

                        try:
                            scan_started = vulns['scan']['started_at']
                            vuln_list.append(scan_started)
                        except KeyError:
                            vuln_list.append(" ")

                        try:
                            scan_uuid = vulns['scan']['uuid']
                            vuln_list.append(scan_uuid)
                        except KeyError:
                            vuln_list.append(" ")

                        try:
                            schedule_id = vulns['scan']['schedule_id']
                            vuln_list.append(schedule_id)
                        except KeyError:
                            vuln_list.append(" ")

                        try:
                            state = vulns['state']
                            vuln_list.append(state)
                        except KeyError:
                            vuln_list.append(" ")
                        try:
                            insert_vulns(vuln_conn, vuln_list)
                        except Error as e:
                            print(e)
                    except IndexError:
                        print("skipped one")
                        end = time.time()
                        print("\nParsing and Saving the data took : " + str(end - dbtime))
        vuln_conn.close()
        vuln_end = time.time()
        print("Total Time : " + str(vuln_end-start))
    except KeyError:
        print("Well this is a bummer; you don't have permissions to download Asset data :( ")
