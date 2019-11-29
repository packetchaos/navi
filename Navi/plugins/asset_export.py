import time
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection, create_table, insert_assets, insert_tags, drop_tables


def asset_export():
    # Set the payload to the maximum number of assets to be pulled at once
    ninty_days = time.time() - 7776000
    pay_load = {"chunk_size": 100, "filters": {"last_assessed": int(ninty_days)}}
    try:
        # request an export of the data
        export = request_data('POST', '/assets/export', payload=pay_load)

        # grab the export UUID
        ex_uuid = export['export_uuid']
        print('Requesting Asset Export with ID : ' + ex_uuid)

        # now check the status
        status = request_data('GET', '/assets/export/' + ex_uuid + '/status')

        # status = get_data('/vulns/export/89ac18d9-d6bc-4cef-9615-2d138f1ff6d2/status')
        print("Status : " + str(status["status"]))

        # set a variable to True for our While loop
        not_ready = True

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(5)
                status = request_data('GET', '/assets/export/' + ex_uuid + '/status')
                print("Status : " + str(status["status"]))

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                not_ready = False

            # Tell the user an error occured
            if status['status'] == 'ERROR':
                print("Error occurred")

        # Crete a new connection to our database
        database = r"navi.db"
        conn = new_db_connection(database)
        drop_tables(conn, 'assets')
        create_asset_table = """CREATE TABLE IF NOT EXISTS assets (
                            ip_address text,
                            hostname text,
                            fqdn text,
                            uuid text PRIMARY KEY,
                            first_found text,
                            last_found text, 
                            operating_system text,
                            mac_address text, 
                            agent_uuid text,
                            last_licensed_scan_date text
                            );"""
        create_table(conn, create_asset_table)
        # create a table for tags
        create_tags_table = """CREATE TABLE IF NOT EXISTS tags (
                            tag_id integer PRIMARY KEY,
                            asset_uuid text,
                            asset_ip,
                            tag_key text,
                            tag_uuid text,
                            tag_value text,
                            tag_added_date text
                            );"""
        create_table(conn, create_tags_table)
        tag_id = 0
        with conn:

            # loop through all of the chunks
            for chunk in status['chunks_available']:
                print("Parsing Chunk {} ...Finished".format(chunk))
                chunk_data = request_data('GET', '/assets/export/' + ex_uuid + '/chunks/' + str(chunk))

                for assets in chunk_data:
                    # create a blank list to append asset details
                    csv_list = []

                    try:
                        # Capture the first IP
                        try:
                            ip = assets['ipv4s'][0]
                            csv_list.append(ip)
                        except:
                            csv_list.append(" ")

                        try:
                            csv_list.append(assets['hostnames'][0])

                        except:

                            csv_list.append(" ")

                        try:
                            csv_list.append(assets['fqdns'][0])
                        except:
                            csv_list.append(" ")

                        try:
                            id = assets['id']
                            csv_list.append(id)
                        except:
                            csv_list.append(" ")
                        try:

                            csv_list.append(assets['first_seen'])
                        except:
                            csv_list.append(" ")
                        try:

                            csv_list.append(assets['last_seen'])
                        except:
                            csv_list.append(" ")
                        try:
                            csv_list.append(assets['operating_systems'][0])
                        except:
                            csv_list.append(" ")

                        try:
                            csv_list.append(assets['mac_addresses'][0])
                        except:
                            csv_list.append(" ")

                        try:
                            csv_list.append(assets['agent_uuid'])
                        except:
                            csv_list.append(" ")

                        try:
                            csv_list.append(assets["last_licensed_scan_date"])
                        except:
                            csv_list.append(" ")

                        try:
                            insert_assets(conn, csv_list)
                        except Error as e:
                            print(e)

                        # cycle through each tag and added it to its own table

                        for t in assets["tags"]:
                            tag_list = []
                            tag_id = tag_id + 1
                            tag_list.append(tag_id)
                            tag_list.append(id)
                            tag_list.append(ip)

                            tag_key = t['key']
                            tag_list.append(tag_key)

                            tag_uuid = t['uuid']
                            tag_list.append(tag_uuid)

                            tag_value = t['value']
                            tag_list.append(tag_value)

                            tag_added_date = t['added_at']
                            tag_list.append(tag_added_date)

                            try:
                                insert_tags(conn, tag_list)
                            except Error as e:
                                print(e)

                    except IndexError:
                        pass


    except KeyError:
        print("Well this is a bummer; you don't have permissions to download Asset data :( ")
