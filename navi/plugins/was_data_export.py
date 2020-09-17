import click
from .dbconfig import create_apps_table, new_db_connection
from .database import insert_apps
from .api_wrapper import request_data


def plugin_parser(plugin_output):
    tech_list = []
    # Split the plugin information on '-'
    plugin_tuple = plugin_output.split('-')
    # Ignore the item in the tuple and add all others to a list
    for x in range(len(plugin_tuple) - 1):
        tech_list.append(str(plugin_tuple[x + 1]))
    return tech_list


def download_data(uuid):
    database = r"navi.db"
    app_conn = new_db_connection(database)
    app_conn.execute('pragma journal_mode=wal;')

    with app_conn:
        create_apps_table()

        apps_table_list = []
        report = request_data('GET', '/was/v2/scans/{}/report'.format(uuid))
        scan_metadata = request_data('GET', '/was/v2/scans/{}'.format(uuid))
        config_id = scan_metadata['config_id']

        # Ignore all scans that have not completed
        if report['scan']['status'] == 'completed':
            scan_name = report['config']['name']
            scan_completed_time = report['scan']['finalized_at']
            try:
                requests_made = scan_metadata['metadata']['progress']['request_count']
            except KeyError:
                requests_made = scan_metadata['metadata']['request_count']
            except TypeError:
                requests_made = 0

            try:
                pages_crawled = scan_metadata['metadata']['progress']['crawled_urls']
            except KeyError:
                try:
                    pages_crawled = scan_metadata['metadata']['audited_urls']
                except KeyError:
                    try:
                        pages_crawled = scan_metadata['metadata']['crawled_urls']
                    except KeyError:
                        pages_crawled = scan_metadata['metadata']['progress']['audited_urls']
            except TypeError:
                pages_crawled = 0
            try:
                pages_audited = scan_metadata['metadata']['progress']['audited_pages']
            except KeyError:
                pages_audited = scan_metadata['metadata']['audited_pages']
            except TypeError:
                pages_audited = 0

            critical = []
            high = []
            medium = []
            low = []
            info = []
            name = report['config']['name']

            critical_summary = []
            high_summary = []
            medium_summary = []
            low_summary = []
            info_summary = []
            tech_list = []
            owasp_list = []
            owasp_dict = {}

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
                        if '2017' in xref['xref_value']:
                            owasp_clean = str(xref['xref_value']).split('-')[1]
                            owasp_list.append(owasp_clean)

            def occurances(number, number_list):
                return number_list.count(number)

            for owasp in range(1, 11):
                owasp_dict["A{}".format(owasp)] = occurances("A{}".format(owasp), owasp_list)

            for finding in report['findings']:
                risk = finding['risk_factor']
                plugin_id = finding['plugin_id']
                plugin_name = finding['name']
                family = finding['family']

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
            apps_table_list.append(pages_audited)
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

            insert_apps(app_conn, apps_table_list)
    return


def grab_scans():
    click.echo("\nDownloading all of your was data\n")
    click.echo("This can take some time...hang tight")
    create_apps_table()

    scan_summaries = []
    params = {"size": "1000"}
    data = request_data('GET', '/was/v2/scans', params=params)
    for scan_data in data['data']:
        was_scan_id = scan_data['scan_id']
        status = scan_data['status']
        # Ignore all scans that have not completed
        if status == 'completed':
            scan_summary = []
            summary_start = scan_data['started_at']
            finish = scan_data['finalized_at']
            application = scan_data['application_uri']
            download_data(was_scan_id)
            scan_summary.append(application)
            scan_summary.append(was_scan_id)
            scan_summary.append(summary_start)
            scan_summary.append(finish)
            scan_summaries.append(scan_summary)
    return
