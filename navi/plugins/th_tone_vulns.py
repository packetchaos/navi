import time
import threading
import click
from queue import Queue
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection, insert_tone_findings
from .dbconfig import create_tone_findings_table

lock = threading.Lock()

q = Queue()


def grab_properties():
    prop_data = request_data('GET', '/api/v1/t1/inventory/findings/properties')
    properties = ""
    for controls in prop_data['data']:
        properties += "{},".format(controls['key'])

    return properties[:-1]


def worker():
    # The worker thread pulls an item from the queue and processes it
    while True:
        item = q.get()
        parse_data(request_data('GET', item))
        q.task_done()


def parse_data(chunk_data):
    database = r"navi.db"
    finding_conn = new_db_connection(database)
    finding_conn.execute('pragma journal_mode=wal;')
    finding_conn.execute('pragma cashe_size=-1000000')
    finding_conn.execute('pragma synchronous=OFF')
    with finding_conn:
        try:
            # loop through all the vulns in this chunk
            for findings in chunk_data:
                # create a blank list to append asset details
                vuln_list = []

                try:
                    try:
                        finding_id = findings['finding_id']
                        vuln_list.append(str(finding_id))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        state = findings['state']
                        vuln_list.append(str(state))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        last_updated = findings['last_updated']
                        vuln_list.append(str(last_updated))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        first_seen = findings['first_observed_at']
                        vuln_list.append(str(first_seen))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        last_seen = findings['last_observed_at']
                        vuln_list.append(str(last_seen))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        port = findings['port']
                        vuln_list.append(str(port))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        protocol = findings['protocol']
                        vuln_list.append(str(protocol))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        detection_id = findings['finding_detection_id']
                        vuln_list.append(str(detection_id))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        finding_name = findings['finding_name']
                        vuln_list.append(str(finding_name))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        solution = findings['finding_solution']
                        vuln_list.append(str(solution))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        severity = findings['finding_severity']
                        vuln_list.append(str(severity))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        vpr = findings['finding_vpr_score']
                        vuln_list.append(str(vpr))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        cves = findings['finding_cves']
                        vuln_list.append(str(cves))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        asset_uuid = findings['asset_id']
                        vuln_list.append(str(asset_uuid))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        asset_name = findings['asset_name']
                        vuln_list.append(str(asset_name))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        asset_class = findings['asset_class']
                        vuln_list.append(str(asset_class))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        active_findings = findings['total_finding_count']
                        vuln_list.append(str(active_findings))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        fixed_findings = findings['fixed_finding_count']
                        vuln_list.append(str(fixed_findings))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        source = findings['sensor_type']
                        vuln_list.append(str(source))
                    except (KeyError, IndexError, TypeError):
                        vuln_list.append(" ")

                    try:
                        insert_tone_findings(finding_conn, vuln_list)
                    except Error as e:
                        click.echo(e)

                except IndexError:
                    click.echo("skipped one")

        except TypeError:
            click.echo("Your Export has no data.  It may have expired")

    finding_conn.close()


def tone_findings_export(ex_uuid, threads):
    start = time.time()
    raw_prop_list = grab_properties()

    # Set URLS for threading
    urls = []

    try:
        if ex_uuid == '0':
            # request an export of the data
            asset_export_id = request_data("POST", "/api/v1/t1/inventory/export/findings?"
                                                   "properties={}&file_format=JSON".format(raw_prop_list))

            # grab the export UUID
            ex_uuid = asset_export_id['export_id']
            click.echo('\nRequesting Tenable One Finding Export with ID : {}'.format(ex_uuid))

            # set a variable to True for our While loop
            not_ready = True
        else:
            click.echo("\nUsing your Export UUID\n")
            not_ready = False

        # now check the status
        status = request_data('GET', '/api/v1/t1/inventory/export/' + ex_uuid + '/status')

        click.echo("Status : {}".format(str(status["status"])))

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(2.5)
                status = request_data('GET', '/api/v1/t1/inventory/export/' + ex_uuid + '/status')

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                ptime = time.time()
                click.echo("\nProcessing Time took : {}".format(str(ptime - start)))
                not_ready = False

            if status['status'] == 'ERROR':
                click.echo("Error occurred")

        create_tone_findings_table()

        for chunks_available in status['chunks_available']:
            urls.append('/api/v1/t1/inventory/export/' + ex_uuid + '/download/' + str(chunks_available))

        for thread in range(threads):
            t = threading.Thread(target=worker)
            t.daemon = True  # thread dies when main thread (only non-daemon thread) exits.
            t.start()

            # stuff work items on the queue (in this case, just a number).
            # start = time.perf_counter()
        for item in range(len(urls)):
            q.put(urls[item])

        q.join()
        end = time.time()
        click.echo("TONE Finding Download took: {}\n".format(str(end - start)))

    except IndexError:
        click.echo("Well this is a bummer; you don't have permissions to download Asset data :( ")
    except TypeError:
        click.echo("You may not be authorized or your keys are invalid")
