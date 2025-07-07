import time
import threading
import click
from queue import Queue
from sqlite3 import Error
from .api_wrapper import request_data
from .database import (new_db_connection, insert_vulns, insert_update_info,
                       get_last_update_id, db_query, insert_plugins)

lock = threading.Lock()

q = Queue()


def worker():
    # The worker thread pulls an item from the queue and processes it
    while True:
        item = q.get()
        chunk_num = item[58:]
        # parse_data(request_data('GET', item))
        data = request_data('GET', item)
        parse_data(data, chunk_num)
        q.task_done()


def parse_data(chunk_data, chunk_number):
    database = r"navi.db"
    vuln_conn = new_db_connection(database)
    vuln_conn.execute('pragma journal_mode=wal;')
    vuln_conn.execute('pragma cashe_size=-1000000')
    vuln_conn.execute('pragma synchronous=OFF')
    with vuln_conn:
        try:
            # loop through all the vulns in this chunk
            for vulns in chunk_data:
                # create a blank list to append asset details
                vuln_list = []
                exploit_list = []

                try:
                    try:
                        finding_id = vulns['finding_id']
                        vuln_list.append(finding_id)
                    except KeyError:
                        click.echo("Every vuln should have a finding Id")
                        vuln_list.append("0")
                    try:
                        ipv4 = vulns['asset']['ipv4']
                        vuln_list.append(ipv4)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        asset_uuid = vulns['asset']['uuid']
                        vuln_list.append(asset_uuid)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        hostname = vulns['asset']['hostname']
                        vuln_list.append(hostname)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        first_found = vulns['first_found']
                        vuln_list.append(first_found)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        last_found = vulns['last_found']
                        vuln_list.append(last_found)
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        output = vulns['output']
                        vuln_list.append(str(output))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        plugin_id = vulns['plugin']['id']
                        vuln_list.append(plugin_id)
                        exploit_list.append(plugin_id)
                    except KeyError:
                        vuln_list.append(" ")
                        exploit_list.append(" ")

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
                        exploit_list.append(severity)
                    except KeyError:
                        vuln_list.append(" ")
                        exploit_list.append(" ")
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
                        cves = vulns['plugin']['cve']
                        vuln_list.append(str(cves))
                        exploit_list.append(str(cves))
                    except KeyError:
                        vuln_list.append(" ")
                        exploit_list.append(" ")

                    try:
                        score = vulns['plugin']['vpr']['score']
                        vuln_list.append(score)
                        exploit_list.append(score)
                    except KeyError:
                        vuln_list.append(" ")
                        exploit_list.append(" ")

                    try:
                        exploit = vulns['plugin']['exploit_available']
                        vuln_list.append(str(exploit))
                        exploit_list.append(str(exploit))
                    except KeyError:
                        vuln_list.append(" ")
                        exploit_list.append(" ")

                    try:
                        xrefs = vulns['plugin']['xrefs']
                        vuln_list.append(str(xrefs))
                        exploit_list.append(str(xrefs))
                    except KeyError:
                        vuln_list.append(" ")
                        exploit_list.append(" ")

                    try:
                        see_also = vulns['plugin']['see_also']
                        exploit_list.append(str(see_also))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cvss3_base_score = vulns['plugin']['cvss3_base_score']
                        exploit_list.append(str(cvss3_base_score))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cvss3_temporal_score = vulns['plugin']['cvss3_temporal_score']
                        exploit_list.append(str(cvss3_temporal_score))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cvss_base_score = vulns['plugin']['cvss_base_score']
                        exploit_list.append(str(cvss_base_score))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        synopsis = vulns['plugin']['synopsis']

                        vuln_list.append(str(synopsis))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        solution = vulns['plugin']['solution']

                        vuln_list.append(str(solution))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        version = vulns['plugin']['version']

                        vuln_list.append(str(version))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        description = vulns['plugin']['description']

                        vuln_list.append(str(description))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        oses = vulns['asset']['operating_system']

                        vuln_list.append(str(oses))
                    except KeyError:
                        vuln_list.append(" ")

                    try:
                        pub_date = vulns['plugin']['publication_date']
                        exploit_list.append(str(pub_date))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        patch_date = vulns['plugin']['patch_publication_date']
                        exploit_list.append(str(patch_date))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        special_url = ("https://cloud.tenable.com/tio/app.html#/"
                                       "vulnerability-management/dashboard/assets/asset-details/"
                                       "{}/vulns/vulnerability-details/{}/details").format(asset_uuid, plugin_id)
                        vuln_list.append(special_url)
                    except AttributeError:
                        special_url = None
                        vuln_list.append(special_url)

                    try:
                        exploit_framework_canvas = vulns['plugin']['exploit_framework_canvas']
                        exploit_list.append(str(exploit_framework_canvas))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploit_framework_core = vulns['plugin']['exploit_framework_core']
                        exploit_list.append(str(exploit_framework_core))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploit_framework_d2_elliot = vulns['plugin']['exploit_framework_d2_elliot']
                        exploit_list.append(str(exploit_framework_d2_elliot))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploit_framework_exploithub = vulns['plugin']['exploit_framework_exploithub']
                        exploit_list.append(str(exploit_framework_exploithub))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploit_framework_metasploit = vulns['plugin']['exploit_framework_metasploit']
                        exploit_list.append(str(exploit_framework_metasploit))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploitability_ease = vulns['plugin']['exploitability_ease']
                        exploit_list.append(str(exploitability_ease))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploited_by_malware = vulns['plugin']['exploited_by_malware']
                        exploit_list.append(str(exploited_by_malware))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploited_by_nessus = vulns['plugin']['exploited_by_nessus']
                        exploit_list.append(str(exploited_by_nessus))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        has_patch = vulns['plugin']['has_patch']
                        exploit_list.append(str(has_patch))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        has_workaround = vulns['plugin']['has_workaround']
                        exploit_list.append(str(has_workaround))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        in_the_news = vulns['plugin']['in_the_news']
                        exploit_list.append(str(in_the_news))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        modification_date = vulns['plugin']['modification_date']
                        exploit_list.append(str(modification_date))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        name = vulns['plugin']['name']
                        exploit_list.append(name)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        risk_factor = vulns['plugin']['risk_factor']
                        exploit_list.append(risk_factor)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        threat_intensity_last28 = vulns['plugin']['vpr']['drivers']['threat_intensity_last28']
                        exploit_list.append(str(threat_intensity_last28))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        threat_sources_last28 = vulns['plugin']['vpr']['drivers']['threat_sources_last28']
                        exploit_list.append(str(threat_sources_last28))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cvss_impact_score_predicted = vulns['plugin']['vpr']['drivers']['cvss_impact_score_predicted']
                        exploit_list.append(cvss_impact_score_predicted)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        threat_sources_last28 = vulns['plugin']['vpr']['drivers']['cvss3_impact_score']
                        exploit_list.append(threat_sources_last28)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        lower_bound = vulns['plugin']['vpr']['drivers']['age_of_vuln']['lower_bound']
                        exploit_list.append(lower_bound)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        upper_bound = vulns['plugin']['vpr']['drivers']['age_of_vuln']['upper_bound']
                        exploit_list.append(upper_bound)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        vpr_updated = vulns['plugin']['vpr']['updated']
                        exploit_list.append(vpr_updated)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cpe = vulns['plugin']['cpe']
                        exploit_list.append(str(cpe))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        url = "https://www.tenable.com/plugins/nessus/{}".format(plugin_id)
                        exploit_list.append(str(url))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        insert_vulns(vuln_conn, vuln_list)
                    except Error as e:
                        click.echo(e)

                    try:
                        insert_plugins(vuln_conn, exploit_list)
                    except Error as e:
                        click.echo(e)
                except IndexError:
                    click.echo("skipped one")

        except TypeError:
            click.echo("Your Export has no data.  It may have expired")
            click.echo("Error on Chunk {}".format(chunk_number))

    click.echo("Chunk {} Finished".format(chunk_number))
    vuln_conn.close()


def vuln_export(days, ex_uuid, threads, category, value, state, severity, vpr_score, operator, plugins):
    start = time.time()

    database = r"navi.db"
    drop_conn = new_db_connection(database)
    drop_conn.execute('pragma journal_mode=wal;')

    # Set URLS for threading
    urls = []

    day = 86400
    new_limit = day * int(days)
    day_limit = time.time() - new_limit

    if category is None:
        if plugins:
            pay_load = {"num_assets": 50, "filters": {'last_found': int(day_limit), "state": state,
                                                      "severity": severity,
                                                      "plugin_id": plugins,
                                                      "vpr_score": {operator: vpr_score}}}
        else:
            pay_load = {"num_assets": 50, "filters": {'last_found': int(day_limit), "state": state,
                                                      "severity": severity,
                                                      "vpr_score": {operator: vpr_score}}}
    else:
        if value is None:
            if plugins:
                pay_load = {"num_assets": 50, "filters": {'last_found': int(day_limit), "state": state,
                                                          "severity": severity,
                                                          "plugin_id": plugins,
                                                          "vpr_score": {operator: vpr_score}}}
            else:
                pay_load = {"num_assets": 50, "filters": {'last_found': int(day_limit),
                                                          "state": state, "severity": severity,
                                                          "vpr_score": {operator: vpr_score}}}
        else:
            if plugins:
                pay_load = {"num_assets": 50, "filters": {'last_found': int(day_limit), "state": state,
                                                          "severity": severity,
                                                          "plugin_id": plugins,
                                                          "vpr_score": {operator: vpr_score},
                                                          "tag.{}".format(category): "[\"{}\"]".format(value)}}
            else:
                pay_load = {"num_assets": 50, "filters": {'last_found': int(day_limit),
                                                          "state": state, "severity": severity,
                                                          "vpr_score": {operator: vpr_score},
                                                          "tag.{}".format(category): "[\"{}\"]".format(value)}}

    try:

        if ex_uuid == '0':
            # request an export of the data
            export = request_data('POST', '/vulns/export', payload=pay_load)

            # grab the export UUID
            ex_uuid = export['export_uuid']
            click.echo('\nRequesting Vulnerability Export with ID : {}'.format(ex_uuid))

            # set a variable to True for our While loop
            not_ready = True
        else:
            click.echo("\nUsing your Export UUID\n")
            not_ready = True

        # now check the status
        status = request_data('GET', '/vulns/export/' + ex_uuid + '/status')

        # status = get_data('/vulns/export/89ac18d9-d6bc-4cef-9615-2d138f1ff6d2/status')
        click.echo("Status : {}".format(str(status["status"])))

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(2.5)
                status = request_data('GET', '/vulns/export/' + ex_uuid + '/status')
                # click.echo("Status : " + str(status["status"]))

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                ptime = time.time()
                click.echo("\nProcessing Time took : {}".format(str(ptime - start)))

                # Display how many chunks there are
                avail = status['total_chunks']
                click.echo("\nChunks Available - {}".format(avail))
                click.echo("Downloading chunks now...hold tight...This can take some time\n")
                not_ready = False

            # Tell the user an error occured
            if status['status'] == 'ERROR':
                click.echo("Error occurred")

        # grab all the chunks and craft the URLS for threading
        for y in status['chunks_available']:
            urls.append('/vulns/export/' + ex_uuid + '/chunks/' + str(y))

        for i in range(threads):
            t = threading.Thread(target=worker)
            t.daemon = True  # thread dies when main thread (only non-daemon thread) exits.
            t.start()

        for item in range(len(urls)):
            q.put(urls[item])

        q.join()
        end = time.time()
        click.echo("Vulnerability Update Time took : {}\n".format(str(end - start)))

        update_id = get_last_update_id()
        diff_dict = [update_id, str(start), str(days), "Vuln update", str(ex_uuid)]
        database_2 = r"navi.db"
        conn = new_db_connection(database_2)
        with conn:
            insert_update_info(conn, diff_dict)

        click.echo("\nCreating a few indexes to make queries faster.\n")
        db_query("CREATE INDEX if NOT EXISTS vulns_plugin_id on vulns (plugin_id);")
        db_query("CREATE INDEX if NOT EXISTS vulns_uuid on vulns (asset_uuid);")

    except KeyError:
        click.echo("Well this is a bummer; you don't have permissions to download Asset data :( ")

    except TypeError:
        click.echo("You may not be authorized or your keys are invalid")
