import time
import threading
from queue import Queue
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection, insert_assets, insert_tags, drop_tables
from .dbconfig import create_assets_table, create_tag_table

lock = threading.Lock()

q = Queue()

tag_id = 0


def worker():
    # The worker thread pulls an item from the queue and processes it
    while True:
        item = q.get()
        parse_data(request_data('GET', item))
        q.task_done()


def parse_data(chunk_data):
    database = r"navi.db"
    asset_conn = new_db_connection(database)
    asset_conn.execute('pragma journal_mode=wal;')

    with asset_conn:
        for assets in chunk_data:
            # create a blank list to append asset details
            csv_list = []

            # Capture the first IP
            try:
                ip = assets['ipv4s'][0]
                csv_list.append(ip)
            except IndexError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['hostnames'][0])
            except IndexError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['fqdns'][0])
            except IndexError:
                csv_list.append(" ")

            try:
                asset_id = assets['id']
                csv_list.append(asset_id)
            except KeyError:
                csv_list.append(" ")
            try:

                csv_list.append(assets['first_seen'])
            except KeyError:
                csv_list.append(" ")
            try:

                csv_list.append(assets['last_seen'])
            except KeyError:
                csv_list.append(" ")
            try:
                csv_list.append(assets['operating_systems'][0])
            except IndexError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['mac_addresses'][0])
            except IndexError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['agent_uuid'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets["last_licensed_scan_date"])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets["network_id"])
            except KeyError:
                csv_list.append(" ")

            try:
                insert_assets(asset_conn, csv_list)
            except Error as e:
                print(e)

        # Collect and save Tag Data
        for tag_assets in chunk_data:
            try:
                global tag_id
                tag_ip = tag_assets['ipv4s'][0]
                tag_asset_id = tag_assets['id']
                for t in tag_assets["tags"]:
                    tag_list = []
                    tag_id = tag_id + 1
                    tag_list.append(tag_id)
                    tag_list.append(tag_asset_id)
                    tag_list.append(tag_ip)

                    tag_key = t['key']
                    tag_list.append(tag_key)

                    tag_uuid = t['uuid']
                    tag_list.append(tag_uuid)

                    tag_value = t['value']
                    tag_list.append(tag_value)

                    tag_added_date = t['added_at']
                    tag_list.append(tag_added_date)

                    try:
                        insert_tags(asset_conn, tag_list)
                    except Error as e:
                        print(e)
            except IndexError:
                pass

    asset_conn.close()


def asset_export(days, ex_uuid, threads):
    start = time.time()
    # Crete a new connection to our database
    database = r"navi.db"
    drop_conn = new_db_connection(database)
    drop_tables(drop_conn, 'assets')
    drop_tables(drop_conn, 'tags')

    # Set URLS for threading
    urls = []

    # Set the payload to the maximum number of assets to be pulled at once
    day = 86400
    new_limit = day * int(days)
    day_limit = time.time() - new_limit
    pay_load = {"chunk_size": 1000, "filters": {"last_assessed": int(day_limit)}}
    try:

        if ex_uuid == '0':
            # request an export of the data
            export = request_data('POST', '/assets/export', payload=pay_load)

            # grab the export UUID
            ex_uuid = export['export_uuid']
            print('\nRequesting Asset Export with ID : ' + ex_uuid)

            # set a variable to True for our While loop
            not_ready = True
        else:
            print("\nUsing your Export UUID\n")
            not_ready = False

        # now check the status
        status = request_data('GET', '/assets/export/' + ex_uuid + '/status')

        # status = get_data('/vulns/export/89ac18d9-d6bc-4cef-9615-2d138f1ffsdf/status')
        print("Status : " + str(status["status"]))

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(15)
                status = request_data('GET', '/assets/export/' + ex_uuid + '/status')
                print("Status : " + str(status["status"]))

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                ptime = time.time()
                print("\nProcessing Time took : " + str(ptime - start))
                not_ready = False

            # Tell the user an error occured
            if status['status'] == 'ERROR':
                print("Error occurred")

        create_assets_table()
        create_tag_table()

        # grab all of the chunks and craft the URLS for threading

        for y in status['chunks_available']:
            urls.append('/assets/export/' + ex_uuid + '/chunks/' + str(y))

        for i in range(threads):
            t = threading.Thread(target=worker)
            t.daemon = True  # thread dies when main thread (only non-daemon thread) exits.
            t.start()

        # stuff work items on the queue (in this case, just a number).
        # start = time.perf_counter()
        for item in range(len(urls)):
            q.put(urls[item])

        q.join()
        end = time.time()
        print(end - start)

    except IndexError:
        print("Well this is a bummer; you don't have permissions to download Asset data :( ")
    except TypeError:
        print("You may not be authorized or your keys are invalid")
