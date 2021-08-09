import time
import threading
import click
from queue import Queue
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection, drop_tables, insert_compliance
from .dbconfig import create_compliance_table

lock = threading.Lock()

q = Queue()


def worker():
    # The worker thread pulls an item from the queue and processes it
    while True:
        item = q.get()
        chunk_num = item[63:]
        # parse_data(request_data('GET', item))
        data = request_data('GET', item)
        parse_data(data, chunk_num)
        q.task_done()


def parse_data(chunk_data, chunk_number):
    database = r"navi.db"
    comply_conn = new_db_connection(database)
    comply_conn.execute('pragma journal_mode=wal;')
    comply_conn.execute('pragma cashe_size=-10000')
    comply_conn.execute('pragma synchronous=OFF')
    with comply_conn:
        try:
            # loop through all of the compliance info in this chunk
            for finding in chunk_data:
                # create a blank list to append asset details
                finding_list = []
                # Try block to ignore assets without IPs
                try:
                    try:
                        asset_uuid = finding['asset_uuid']
                        finding_list.append(asset_uuid)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        actual_value = finding['actual_value']
                        finding_list.append(actual_value)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        audit_file = finding['audit_file']
                        finding_list.append(audit_file)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        check_id = finding['check_id']
                        finding_list.append(check_id)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        check_info = finding['check_info']
                        finding_list.append(check_info)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        check_name = finding['check_name']
                        finding_list.append(check_name)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        expected_value = finding['expected_value']
                        finding_list.append(expected_value)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        first_seen = finding['first_seen']
                        finding_list.append(first_seen)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        last_seen = finding['last_seen']
                        finding_list.append(last_seen)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        plugin_id = finding['plugin_id']
                        finding_list.append(plugin_id)
                    except KeyError:
                        finding_list.append(" ")

                    # Need to break this into it's own table.
                    try:
                        reference = str(finding['reference'])
                        finding_list.append(reference)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        see_also = finding['see_also']
                        finding_list.append(see_also)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        solution = finding['solution']
                        finding_list.append(solution)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        check_status = finding['status']
                        finding_list.append(check_status)
                    except KeyError:
                        finding_list.append(" ")

                    try:
                        insert_compliance(comply_conn, finding_list)
                    except Error as e:
                        click.echo(e)

                except IndexError:
                    click.echo("skipped one")
        except TypeError:
            click.echo("Your Export has no data.  It may have expired")
            click.echo("Error on Chunk {}".format(chunk_number))

    click.echo("Chunk {} Finished".format(chunk_number))
    comply_conn.close()


def compliance_export(days, ex_uuid, threads):
    start = time.time()

    database = r"navi.db"
    drop_conn = new_db_connection(database)
    drop_conn.execute('pragma journal_mode=wal;')

    # Right now we just drop the table.  Eventually I will actually update the database
    drop_tables(drop_conn, 'compliance')

    create_compliance_table()

    # Set URLS for threading
    urls = []

    # Set the payload to the maximum number of assets to be pulled at once
    day = 86400
    new_limit = day * int(days)
    day_limit = time.time() - new_limit
    pay_load = {"num_findings": 50, "filters": {'last_seen': int(day_limit)}}
    try:

        if ex_uuid == '0':
            # request an export of the data
            export = request_data('POST', '/compliance/export', payload=pay_load)

            # grab the export UUID
            ex_uuid = export['export_uuid']
            click.echo('\nRequesting Compliance Export with ID : {}'.format(ex_uuid))

            # set a variable to True for our While loop
            not_ready = True
        else:
            click.echo("\nUsing your Export UUID\n")
            not_ready = True

        # now check the status
        status = request_data('GET', '/compliance/export/' + ex_uuid + '/status')

        # status
        click.echo("Status : {}".format(str(status["status"])))

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(2.5)
                status = request_data('GET', '/compliance/export/' + ex_uuid + '/status')
                # click.echo("Status : " + str(status["status"]))

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                ptime = time.time()
                click.echo("\nProcessing Time took : {}".format(str(ptime - start)))

                # Display how many chunks there are
                avail = len(status['chunks_available'])
                click.echo("\nChunks Available - {}".format(avail))
                click.echo("Downloading chunks now...hold tight...This can take some time\n")
                not_ready = False

            # Tell the user an error occurred
            if status['status'] == 'ERROR':
                click.echo("\nT.io Error occurred\n Try again!")
                exit()

        # grab all of the chunks and craft the URLS for threading
        for y in status['chunks_available']:
            urls.append('/compliance/export/' + ex_uuid + '/chunks/' + str(y))

        for i in range(threads):
            t = threading.Thread(target=worker)
            t.daemon = True  # thread dies when main thread (only non-daemon thread) exits.
            t.start()

        for item in range(len(urls)):
            q.put(urls[item])

        q.join()
        end = time.time()
        click.echo("Compliance Update Time took : {}\n".format(str(end - start)))

    except KeyError:
        click.echo("Well this is a bummer; you don't have permissions to download Asset data :( ")

    except TypeError:
        click.echo("You may not be authorized or your keys are invalid")
