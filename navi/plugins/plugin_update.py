
import time
import threading
import click
from queue import Queue
from sqlite3 import Error
from .api_wrapper import request_data
from .dbconfig import create_plugins_table
from .database import new_db_connection, insert_plugins

lock = threading.Lock()

q = Queue()


def parse_data(page_info):
    database = r"navi.db"
    plugin_conn = new_db_connection(database)
    plugin_conn.execute('pragma journal_mode=wal;')
    plugin_conn.execute('pragma cashe_size=-1000000')
    plugin_conn.execute('pragma synchronous=OFF')
    with plugin_conn:
        try:
            # loop through all the vulns in this chunk
            for plug_info in page_info['data']['plugin_details']:
                import pprint
                #pprint.pprint(plug_info)
                # create a blank list to append asset details
                exploit_list = []

                try:
                    try:
                        plugin_id = plug_info['id']
                        exploit_list.append(plugin_id)
                    except KeyError:
                        plugin_id="None"
                        exploit_list.append(" ")

                    try:
                        severity = plug_info['attributes']['vendor_severity']

                        exploit_list.append(severity)
                    except KeyError:

                        exploit_list.append(" ")

                    try:
                        cves = plug_info['attributes']['cve']

                        exploit_list.append(str(cves))
                    except KeyError:

                        exploit_list.append(" ")

                    try:
                        score = plug_info['attributes']['vpr']['score']

                        exploit_list.append(score)
                    except KeyError:

                        exploit_list.append(" ")

                    try:
                        exploit = plug_info['attributes']['exploit_available']

                        exploit_list.append(str(exploit))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        xrefs = plug_info['attributes']['xref']
                        exploit_list.append(str(xrefs))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        see_also = plug_info['attributes']['see_also']
                        exploit_list.append(str(see_also))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cvss3_base_score = plug_info['attributes']['cvss3_base_score']
                        exploit_list.append(str(cvss3_base_score))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cvss3_temporal_score = plug_info['attributes']['cvss3_temporal_score']
                        exploit_list.append(str(cvss3_temporal_score))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cvss_base_score = plug_info['attributes']['cvss_base_score']
                        exploit_list.append(str(cvss_base_score))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        pub_date = plug_info['attributes']['vuln_publication_date']
                        exploit_list.append(str(pub_date))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        patch_date = plug_info['attributes']['patch_publication_date']
                        exploit_list.append(str(patch_date))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploit_framework_canvas = plug_info['attributes']['exploit_framework_canvas']
                        exploit_list.append(str(exploit_framework_canvas))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploit_framework_core = plug_info['attributes']['exploit_framework_core']
                        exploit_list.append(str(exploit_framework_core))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploit_framework_d2_elliot = plug_info['attributes']['exploit_framework_d2_elliot']
                        exploit_list.append(str(exploit_framework_d2_elliot))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploit_framework_exploithub = plug_info['attributes']['exploit_framework_exploithub']
                        exploit_list.append(str(exploit_framework_exploithub))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploit_framework_metasploit = plug_info['attributes']['exploit_framework_metasploit']
                        exploit_list.append(str(exploit_framework_metasploit))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploitability_ease = plug_info['attributes']['exploitability_ease']
                        exploit_list.append(str(exploitability_ease))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        solution = plug_info['attributes']['solution']
                        exploit_list.append(str(solution))
                    except KeyError:
                        exploit_list.append(" ")
                    try:
                        description = plug_info['attributes']['description']
                        exploit_list.append(str(description))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploited_by_malware = plug_info['attributes']['exploited_by_malware']
                        exploit_list.append(str(exploited_by_malware))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        exploited_by_nessus = plug_info['attributes']['exploited_by_nessus']
                        exploit_list.append(str(exploited_by_nessus))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        has_patch = plug_info['attributes']['has_patch']
                        exploit_list.append(str(has_patch))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        has_workaround = plug_info['attributes']['has_workaround']
                        exploit_list.append(str(has_workaround))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        in_the_news = plug_info['attributes']['in_the_news']
                        exploit_list.append(str(in_the_news))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        modification_date = plug_info['attributes']['modification_date']
                        exploit_list.append(str(modification_date))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        name = plug_info['name']
                        exploit_list.append(name)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        risk_factor = plug_info['attributes']['risk_factor']
                        exploit_list.append(risk_factor)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        threat_intensity_last28 = plug_info['attributes']['vpr']['drivers']['threat_intensity_last28']
                        exploit_list.append(str(threat_intensity_last28))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        threat_sources_last28 = plug_info['attributes']['vpr']['drivers']['threat_sources_last28']
                        exploit_list.append(str(threat_sources_last28))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cvss_impact_score_predicted = plug_info['attributes']['vpr']['drivers']['cvss_impact_score_predicted']
                        exploit_list.append(cvss_impact_score_predicted)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        threat_sources_last28 = plug_info['attributes']['vpr']['drivers']['cvss3_impact_score']
                        exploit_list.append(threat_sources_last28)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        lower_bound = plug_info['attributes']['vpr']['drivers']['age_of_vuln']['lower_bound']
                        exploit_list.append(lower_bound)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        upper_bound = plug_info['attributes']['vpr']['drivers']['age_of_vuln']['upper_bound']
                        exploit_list.append(upper_bound)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        vpr_updated = plug_info['attributes']['vpr']['updated']
                        exploit_list.append(vpr_updated)
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        cpe = plug_info['attributes']['cpe']
                        exploit_list.append(str(cpe))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        url = "https://www.tenable.com/plugins/nessus/{}".format(plugin_id)
                        exploit_list.append(str(url))
                    except KeyError:
                        exploit_list.append(" ")

                    try:
                        insert_plugins(plugin_conn, exploit_list)
                    except Error as e:
                        click.echo(e)
                except IndexError:
                    click.echo("skipped one")

        except TypeError:
            click.echo("Your Export has no data.  It may have expired")

    plugin_conn.close()
    return


def plugin_export(size):

    database = r"navi.db"
    drop_conn = new_db_connection(database)
    drop_conn.execute('pragma journal_mode=wal;')
    create_plugins_table()
    try:
        # Last total plugin Check:
        total = 281470
        page_total = 29

        for pages in range(1, int(page_total)):
            print("going through page {}".format(pages))
            page_info = request_data('GET', '/plugins/plugin?size=10000&page={}'.format(pages))
            parse_data(page_info)
        print("\nPlugins downloaded\n")

    except KeyError:
        click.echo("Well this is a bummer; you don't have permissions to download Asset data :( ")

    except TypeError:
        click.echo("You may not be authorized or your keys are invalid")
