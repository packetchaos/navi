import time
import threading
import click
from queue import Queue
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection, insert_tone_assets
from .dbconfig import create_tone_assets_table

lock = threading.Lock()

q = Queue()

tag_id = 0


def grab_properties():
    properties = ""
    #prop_data = request_data('GET', '/api/v1/t1/inventory/assets/properties')
    props = ['acr', 'aes', 'asset_class', 'asset_id', 'asset_name', 'cloud_id_name', 'created_at',
             'critical_vuln_count', 'critical_weakness_count','entitlement_count', 'exposure_classes',
             'first_observed_at', 'fqdns', 'high_vuln_count', 'high_weakness_count', 'is_licensed','last_licensed_at',
             'last_observed_at', 'last_updated', 'license_expires_at', 'low_vuln_count', 'low_weakness_count',
             'medium_vuln_count',
             'medium_weakness_count',
             'sensors',
             'sources',
             'tag_count',
             'tag_ids',
             'tenable_uuid',
             'total_weakness_count',
             'host_name',
             'ipv4_addresses',
             'ipv6_addresses',
             'operating_systems',
             'external_identifier',
             'external_tags',
             'mac_addresses',
             'custom_attributes',
             'total_finding_count']
    for controls in props: #prop_data['data']:
        properties += "{},".format(controls)#['key'])

    return properties[:-1]


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
            # --------------------
            # Required properties
            # --------------------

            try:
                acr = assets['acr']
                csv_list.append(str(acr))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                aes = assets['aes']
                csv_list.append(str(aes))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                asset_class = assets['asset_class']
                csv_list.append(str(asset_class))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                asset_id = assets['asset_id']
                csv_list.append(str(asset_id))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                asset_name = assets['asset_name']
                csv_list.append(str(asset_name))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                cloud_id_name = assets['cloud_id_name']
                csv_list.append(str(cloud_id_name))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                created_at = assets['created_at']
                csv_list.append(str(created_at))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                critical_vuln_count = assets['critical_vuln_count']
                csv_list.append(str(critical_vuln_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                critical_weakness_count = assets['critical_weakness_count']
                csv_list.append(str(critical_weakness_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                entitlement_count = assets['entitlement_count']
                csv_list.append(str(entitlement_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                exposure_classes = assets['exposure_classes']
                csv_list.append(str(exposure_classes))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                first_observed_at = assets['first_observed_at']
                csv_list.append(str(first_observed_at))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                fqdns = assets['fqdns']
                csv_list.append(str(fqdns))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                high_vuln_count = assets['high_vuln_count']
                csv_list.append(str(high_vuln_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                high_weakness_count = assets['high_weakness_count']
                csv_list.append(str(high_weakness_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                is_licensed = assets['is_licensed']
                csv_list.append(str(is_licensed))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                last_licensed_at = assets['last_licensed_at']
                csv_list.append(str(last_licensed_at))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                last_observed_at = assets['last_observed_at']
                csv_list.append(str(last_observed_at))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                last_updated = assets['last_updated']
                csv_list.append(str(last_updated))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                license_expires_at = assets['license_expires_at']
                csv_list.append(str(license_expires_at))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                low_vuln_count = assets['low_vuln_count']
                csv_list.append(str(low_vuln_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                low_weakness_count = assets['low_weakness_count']
                csv_list.append(str(low_weakness_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                medium_vuln_count = assets['medium_vuln_count']
                csv_list.append(str(medium_vuln_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                medium_weakness_count = assets['medium_weakness_count']
                csv_list.append(str(medium_weakness_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                sensors = assets['sensors']
                csv_list.append(str(sensors))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                sources = assets['sources']
                csv_list.append(str(sources))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                tag_count = assets['tag_count']
                csv_list.append(str(tag_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                tag_ids = assets['tag_ids']
                csv_list.append(str(tag_ids))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                tenable_uuid = assets['tenable_uuid']
                csv_list.append(str(tenable_uuid))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                total_weakness_count = assets['total_weakness_count']
                csv_list.append(str(total_weakness_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                host_name = assets['host_name']
                csv_list.append(str(host_name))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                ipv4_addresses = assets['ipv4_addresses']
                csv_list.append(str(ipv4_addresses))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                ipv6_addresses = assets['ipv6_addresses']
                csv_list.append(str(ipv6_addresses))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                operating_systems = assets['operating_systems']
                csv_list.append(str(operating_systems))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                external_identifier = assets['external_identifier']
                csv_list.append(str(external_identifier))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                external_tags = assets['external_tags']
                csv_list.append(str(external_tags))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                mac_addresses = assets['mac_addresses']
                csv_list.append(str(mac_addresses))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                custom_attributes = assets['custom_attributes']
                csv_list.append(str(custom_attributes))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                total_finding_count = assets['total_finding_count']
                csv_list.append(str(total_finding_count))
            except (KeyError, IndexError, TypeError):
                csv_list.append(" ")

            try:
                insert_tone_assets(asset_conn, csv_list)
            except Error as e:
                click.echo(e)
    asset_conn.close()


def tone_export(ex_uuid, threads):
    start = time.time()
    raw_prop_list = grab_properties()

    # Set URLS for threading
    urls = []

    try:
        if ex_uuid == '0':
            # request an export of the data
            asset_export_id = request_data("POST", "/api/v1/t1/inventory/export/assets?"
                                                   "properties={}&file_format=JSON".format(raw_prop_list))

            # grab the export UUID
            ex_uuid = asset_export_id['export_id']
            click.echo('\nRequesting Tenable One Asset Export with ID : {}'.format(ex_uuid))

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

        create_tone_assets_table()

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
        click.echo("TONE Asset Download took: {}\n".format(str(end - start)))

    except IndexError:
        click.echo("Well this is a bummer; you don't have permissions to download Asset data :( ")
    except TypeError:
        click.echo("You may not be authorized or your keys are invalid")

