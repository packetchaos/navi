from .dbconfig import create_apps_table, new_db_connection, create_plugins_table
from .database import insert_apps, insert_plugins, drop_tables
from .api_wrapper import request_data
import click
import time
import datetime

def plugin_parser(plugin_output):
    tech_list = []
    # Split the plugin information on '-'
    plugin_tuple = plugin_output.split('-')
    # Ignore the item in the tuple and add all others to a list
    for x in range(len(plugin_tuple) - 1):
        tech_list.append(str(plugin_tuple[x + 1]))
    return tech_list


def vuln_counter(plugin_id, scan_uuid):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT count(*) from plugins where plugin_id =='{}' and scan_uuid=='{}';".format(plugin_id, scan_uuid))

        plugin_data = cur.fetchall()

        return plugin_data[0][0]


def get_was_stats(scan_id):
    params = {"limit": "200", "offset": "0"}
    was_data = request_data("POST", "/was/v2/scans/{}/vulnerabilities/search".format(scan_id), params=params)
    stat_dict = {}

    for finding in was_data['items']:
        if str(finding['plugin_id']) == '98000':

            scan_meta_data = finding['details']['output']

            new_data = str(scan_meta_data).split()

            stat_dict['eng_version'] = "0"#new_data[2]
            stat_dict['start_time'] = "0"#"{} {} {}".format(new_data[11], new_data[12],new_data[13])
            stat_dict['duration'] = "0"#new_data[15]

            stat_dict['requests_made'] = "0"#new_data[17]
            stat_dict['crawler_requests'] = "0"#new_data[20]
            stat_dict['requests_per_sec'] = "0"#new_data[22]
            stat_dict['mean_response_time'] = "0"#new_data[26]

            stat_dict['data_target'] = "0"#"{} {}".format(new_data[33], new_data[34])
            stat_dict['target_to_data'] = "0"#"{} {}".format(new_data[39], new_data[40])

            stat_dict['network_timeouts'] = "0"#new_data[45]
            stat_dict['browser_timeouts'] = "0"#new_data[48]
            stat_dict['browser_respawns'] = "0"#new_data[51]

            return stat_dict


def download_data(uuid, asset):
    database = r"navi.db"
    app_conn = new_db_connection(database)
    app_conn.execute('pragma journal_mode=wal;')
    with app_conn:
        apps_table_list = []
        report = request_data('GET', '/was/v2/scans/{}/report'.format(uuid))
        #scan_metadata = get_was_stats(uuid)

        config_id = report['config']['config_id']

        # Ignore all scans that have not completed
        if report['scan']['status'] == 'completed':
            scan_name = report['config']['name']

            scan_completed_time = report['scan']['finalized_at']
            try:
                requests_made = 0#scan_metadata['requests_made']
            except KeyError:
                requests_made = 0

            try:
                pages_crawled = 0#scan_metadata['crawler_requests']
            except KeyError:
                pages_crawled = 0

            critical = []
            high = []
            medium = []
            low = []
            info = []
            critical_summary = []
            high_summary = []
            medium_summary = []
            low_summary = []
            info_summary = []
            tech_list = ['Nothing Found']
            owasp_list = []
            owasp_dict = {}
            try:
                notes = report['config']['notes']
            except KeyError:
                notes = "No Scan Notes"

            try:
                target = report['scan']['target']
            except KeyError:
                target = report['config']['settings']['target']

            # Count for-loop
            plugin_list = []

            for finding in report['findings']:
                plugin_list.append(finding['plugin_id'])
                for xref in finding['xrefs']:
                    # Grab multiples values here
                    if xref['xref_name'] == 'OWASP':
                        if '2021' in xref['xref_value']:
                            owasp_clean = str(xref['xref_value']).split('-')[1]
                            owasp_list.append(owasp_clean)

            def occurances(number, number_list):
                return number_list.count(number)

            for owasp in range(1, 11):
                owasp_dict["A{}".format(owasp)] = occurances("A{}".format(owasp), owasp_list)

            for finding in report['findings']:
                finding_list = []
                risk = finding['risk_factor']
                plugin_id = finding['plugin_id']
                plugin_name = finding['name']
                family = finding['family']
                cves = finding['cves']
                description = finding['description']
                output = finding['output']
                owasp = finding['owasp']
                payload = finding['payload']
                plugin_mod_date = finding['plugin_modification_date']
                plugin_pub_date = finding['plugin_publication_date']
                proof = finding['proof']
                request_headers = finding['request_headers']
                response_headers = finding['response_headers']
                solution = finding['solution']
                url = finding['uri']
                xrefs = finding['xrefs']
                see_also = finding['see_also']

                finding_list.append(str(uuid))
                finding_list.append(str(plugin_name))
                finding_list.append(str(cves))
                finding_list.append(str(description))
                finding_list.append(str(family))
                finding_list.append(str(output))
                finding_list.append(str(owasp))
                finding_list.append(str(payload))
                finding_list.append(str(plugin_id))
                finding_list.append(str(plugin_mod_date))
                finding_list.append(str(plugin_pub_date))
                finding_list.append(str(proof))
                finding_list.append(str(request_headers))
                finding_list.append(str(response_headers))
                finding_list.append(str(risk))
                finding_list.append(str(solution))
                finding_list.append(str(url))
                finding_list.append(str(xrefs))
                finding_list.append(str(see_also))

                insert_plugins(app_conn, finding_list)

                if str(plugin_id) == '98059':
                    tech_list = plugin_parser(finding['output'])

                vuln_count = occurances(finding['plugin_id'], plugin_list)
                vuln_list = [risk, plugin_id, plugin_name, family, vuln_count]
                if risk == 'high':
                    high.append(plugin_id)
                    if vuln_list not in high_summary:
                        high_summary.append(vuln_list)
                elif risk == 'medium':
                    medium.append(plugin_id)
                    if vuln_list not in medium_summary:
                        medium_summary.append(vuln_list)
                elif risk == 'low':
                    low.append(plugin_id)
                    if vuln_list not in low_summary:
                        low_summary.append(vuln_list)
                elif risk == 'critical':
                    critical.append(plugin_id)
                    if vuln_list not in critical_summary:
                        critical_summary.append(vuln_list)
                else:
                    info.append(plugin_id)
                    if vuln_list not in info_summary:
                        info_summary.append(vuln_list)

            apps_table_list.append(scan_name)
            apps_table_list.append(uuid)
            apps_table_list.append(target)
            apps_table_list.append(scan_completed_time)
            apps_table_list.append(pages_crawled)
            apps_table_list.append(requests_made)
            apps_table_list.append(len(critical))
            apps_table_list.append(len(high))
            apps_table_list.append(len(medium))
            apps_table_list.append(len(low))
            apps_table_list.append(len(info))
            apps_table_list.append(str(owasp_dict))
            apps_table_list.append(str(tech_list))
            apps_table_list.append(config_id)
            apps_table_list.append(str(notes))
            apps_table_list.append(str(asset))

            insert_apps(app_conn, apps_table_list)

    return


def grab_scans(days):
    click.echo("\nDownloading all Completed Scans for the last {} days.\n"
               "This will take some time.\n".format(days))
    database = r"navi.db"
    app_conn = new_db_connection(database)
    app_conn.execute('pragma journal_mode=wal;')

    drop_tables(app_conn, 'apps')
    drop_tables(app_conn, 'plugins')

    create_apps_table()

    create_plugins_table()
    data = request_data('POST', '/was/v2/configs/search?limit=200&offset=0')
    for configs in data['items']:
        config_id = configs['config_id']
        was_config_data = request_data("POST", "/was/v2/configs/{}/scans/search".format(config_id))
        # Ignore all scans that have not completed

        for scanids in was_config_data['items']:
            day = 86400
            new_limit = day * int(days)
            day_limit = time.time() - new_limit

            if scanids['status'] == 'completed':
                asset_uuid = scanids['asset_id']
                was_scan_id = scanids['scan_id']
                finalized_at = scanids['finalized_at']
                epoch = datetime.datetime.strptime(finalized_at, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()

                if epoch >= day_limit:
                    download_data(was_scan_id, asset_uuid)

