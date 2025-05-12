import time
import threading
import click
from queue import Queue
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection, insert_assets, insert_tags, drop_tables, get_last_update_id, insert_update_info
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
                csv_list.append(assets["acr_score"])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets["exposure_score"])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['aws_ec2_instance_id'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['aws_ec2_instance_state'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['aws_ec2_name'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['aws_ec2_region'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['aws_availability_zone'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['gcp_instance_id'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['gcp_project_id'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['gcp_zone'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['azure_location'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['azure_resource_group'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['azure_resource_id'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['azure_subscription_id'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['azure_type'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(assets['azure_vm_id'])
            except KeyError:
                csv_list.append(" ")

            try:
                special_url = ("https://cloud.tenable.com/tio/app.html#/"
                               "vulnerability-management/dashboard/assets/asset-details/{}/vulns").format(asset_id)
                csv_list.append(special_url)
            except:
                special_url = None
                csv_list.append(special_url)

            # Collect and save Tag Data
            try:
                global tag_id
                tag_ip = assets['ipv4s'][0]
                tag_asset_id = assets['id']
                for t in assets["tags"]:
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
                        click.echo(e)
            except IndexError:
                pass
            try:
                insert_assets(asset_conn, csv_list)
            except Error as e:
                click.echo(e)
    asset_conn.close()


def asset_export(days, ex_uuid, threads, category, value):
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
    if category is None:
        pay_load = {"chunk_size": 1000, "filters": {"last_assessed": int(day_limit)}}
    else:
        if value is None:
            pay_load = {"chunk_size": 1000, "filters": {"last_assessed": int(day_limit)}}
        else:
            pay_load = {"chunk_size": 1000, "filters": {"last_assessed": int(day_limit),
                                                        "tag.{}".format(category): value}}
    try:

        if ex_uuid == '0':
            # request an export of the data
            export = request_data('POST', '/assets/export', payload=pay_load)

            # grab the export UUID
            ex_uuid = export['export_uuid']
            click.echo('\nRequesting Asset Export with ID : {}'.format(ex_uuid))

            # set a variable to True for our While loop
            not_ready = True
        else:
            click.echo("\nUsing your Export UUID\n")
            not_ready = False

        # now check the status
        status = request_data('GET', '/assets/export/' + ex_uuid + '/status')

        click.echo("Status : {}".format(str(status["status"])))

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(2.5)
                status = request_data('GET', '/assets/export/' + ex_uuid + '/status')

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                ptime = time.time()
                click.echo("\nProcessing Time took : {}".format(str(ptime - start)))
                not_ready = False

            if status['status'] == 'ERROR':
                click.echo("Error occurred")

        create_assets_table()
        create_tag_table()

        # grab all the chunks and craft the URLS for threading

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
        click.echo("Asset Download took: {}\n".format(str(end - start)))

        # Now that the download has completed we need to record it
        update_id = get_last_update_id()

        # need to ignore if the Ex_uuid exists in the db.
        diff_dict = [update_id, str(start), str(days), "Asset Update", str(ex_uuid)]
        database_2 = r"navi.db"
        conn = new_db_connection(database_2)
        with conn:
            insert_update_info(conn, diff_dict)

    except IndexError:
        click.echo("Well this is a bummer; you don't have permissions to download Asset data :( ")
    except TypeError:
        click.echo("You may not be authorized or your keys are invalid")