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
                    asset_id = findings['asset_id']
                    vuln_list.append(str(asset_id))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

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
                    first_observed_at = findings['first_observed_at']
                    vuln_list.append(str(first_observed_at))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    last_observed_at = findings['last_observed_at']
                    vuln_list.append(str(last_observed_at))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    last_fixed_at = findings['last_fixed_at']
                    vuln_list.append(str(last_fixed_at))
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
                    cpes = findings['cpes']
                    vuln_list.append(str(cpes))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_parent_detection_id = findings['finding_parent_detection_id']
                    vuln_list.append(str(finding_parent_detection_id))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_detection_id = findings['finding_detection_id']
                    vuln_list.append(str(finding_detection_id))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_provider_code = findings['finding_provider_code']
                    vuln_list.append(str(finding_provider_code))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_product_code = findings['finding_product_code']
                    vuln_list.append(str(finding_product_code))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_provider_detection_id = findings['finding_provider_detection_id']
                    vuln_list.append(str(finding_provider_detection_id))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_detection_code = findings['finding_detection_code']
                    vuln_list.append(str(finding_detection_code))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_detection_version = findings['finding_detection_version']
                    vuln_list.append(str(finding_detection_version))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_detection_variant = findings['finding_detection_variant']
                    vuln_list.append(str(finding_detection_variant))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_detection_sub_category = findings['finding_detection_sub_category']
                    vuln_list.append(str(finding_detection_sub_category))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_resource_type = findings['finding_resource_type']
                    vuln_list.append(str(finding_resource_type))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_detection_family = findings['finding_detection_family']
                    vuln_list.append(str(finding_detection_family))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_detection_type = findings['finding_detection_type']
                    vuln_list.append(str(finding_detection_type))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_intel_type = findings['finding_intel_type']
                    vuln_list.append(str(finding_intel_type))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_name = findings['finding_name']
                    vuln_list.append(str(finding_name))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_synopsis = findings['finding_synopsis']
                    vuln_list.append(str(finding_synopsis))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_description = findings['finding_description']
                    vuln_list.append(str(finding_description))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_solution = findings['finding_solution']
                    vuln_list.append(str(finding_solution))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_script_file_name = findings['finding_script_file_name']
                    vuln_list.append(str(finding_script_file_name))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_exploit_maturity = findings['finding_exploit_maturity']
                    vuln_list.append(str(finding_exploit_maturity))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_detection_published_at = findings['finding_detection_published_at']
                    vuln_list.append(str(finding_detection_published_at))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_vuln_published_at = findings['finding_vuln_published_at']
                    vuln_list.append(str(finding_vuln_published_at))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_patch_published_at = findings['finding_patch_published_at']
                    vuln_list.append(str(finding_patch_published_at))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_first_covered_at = findings['finding_first_covered_at']
                    vuln_list.append(str(finding_first_covered_at))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_first_functional_exploit_at = findings['finding_first_functional_exploit_at']
                    vuln_list.append(str(finding_first_functional_exploit_at))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_first_poc_at = findings['finding_first_poc_at']
                    vuln_list.append(str(finding_first_poc_at))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cisa_kev_added_date = findings['finding_cisa_kev_added_date']
                    vuln_list.append(str(finding_cisa_kev_added_date))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cisa_kev_due_date = findings['finding_cisa_kev_due_date']
                    vuln_list.append(str(finding_cisa_kev_due_date))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_epss_scored_at = findings['finding_epss_scored_at']
                    vuln_list.append(str(finding_epss_scored_at))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_severity_driver = findings['finding_severity_driver']
                    vuln_list.append(str(finding_severity_driver))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_severity = findings['finding_severity']
                    vuln_list.append(str(finding_severity))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_severity_level = findings['finding_severity_level']
                    vuln_list.append(str(finding_severity_level))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_risk_factor = findings['finding_risk_factor']
                    vuln_list.append(str(finding_risk_factor))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_risk_severity_level = findings['finding_risk_severity_level']
                    vuln_list.append(str(finding_risk_severity_level))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_vpr_score = findings['finding_vpr_score']
                    vuln_list.append(str(finding_vpr_score))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_vpr2_score = findings['finding_vpr2_score']
                    vuln_list.append(str(finding_vpr2_score))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_vpr_risk_factor = findings['finding_vpr_risk_factor']
                    vuln_list.append(str(finding_vpr_risk_factor))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_vpr_severity_level = findings['finding_vpr_severity_level']
                    vuln_list.append(str(finding_vpr_severity_level))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_exploitability_ease_code = findings['finding_exploitability_ease_code']
                    vuln_list.append(str(finding_exploitability_ease_code))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_exploitability_ease = findings['finding_exploitability_ease']
                    vuln_list.append(str(finding_exploitability_ease))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss2_source = findings['finding_cvss2_source']
                    vuln_list.append(str(finding_cvss2_source))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss2_base_score = findings['finding_cvss2_base_score']
                    vuln_list.append(str(finding_cvss2_base_score))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss2_base_vector = findings['finding_cvss2_base_vector']
                    vuln_list.append(str(finding_cvss2_base_vector))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss2_temporal_score = findings['finding_cvss2_temporal_score']
                    vuln_list.append(str(finding_cvss2_temporal_score))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss2_temporal_vector = findings['finding_cvss2_temporal_vector']
                    vuln_list.append(str(finding_cvss2_temporal_vector))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss3_source = findings['finding_cvss3_source']
                    vuln_list.append(str(finding_cvss3_source))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss3_base_score = findings['finding_cvss3_base_score']
                    vuln_list.append(str(finding_cvss3_base_score))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss3_base_vector = findings['finding_cvss3_base_vector']
                    vuln_list.append(str(finding_cvss3_base_vector))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss3_temporal_score = findings['finding_cvss3_temporal_score']
                    vuln_list.append(str(finding_cvss3_temporal_score))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss3_temporal_vector = findings['finding_cvss3_temporal_vector']
                    vuln_list.append(str(finding_cvss3_temporal_vector))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss4_source = findings['finding_cvss4_source']
                    vuln_list.append(str(finding_cvss4_source))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss4_score = findings['finding_cvss4_score']
                    vuln_list.append(str(finding_cvss4_score))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss4_vector = findings['finding_cvss4_vector']
                    vuln_list.append(str(finding_cvss4_vector))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cvss4_threat_metrics = findings['finding_cvss4_threat_metrics']
                    vuln_list.append(str(finding_cvss4_threat_metrics))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_epss_score = findings['finding_epss_score']
                    vuln_list.append(str(finding_epss_score))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_epss_percentile = findings['finding_epss_percentile']
                    vuln_list.append(str(finding_epss_percentile))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_stig_severity = findings['finding_stig_severity']
                    vuln_list.append(str(finding_stig_severity))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_is_security_control = findings['finding_is_security_control']
                    vuln_list.append(str(finding_is_security_control))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_is_deprecated = findings['finding_is_deprecated']
                    vuln_list.append(str(finding_is_deprecated))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cves = findings['finding_cves']
                    vuln_list.append(str(finding_cves))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_cwes = findings['finding_cwes']
                    vuln_list.append(str(finding_cwes))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    finding_metadata_file_name = findings['finding_metadata_file_name']
                    vuln_list.append(str(finding_metadata_file_name))
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
                    acr = findings['acr']
                    vuln_list.append(str(acr))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    aes = findings['aes']
                    vuln_list.append(str(aes))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    is_licensed = findings['is_licensed']
                    vuln_list.append(str(is_licensed))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    total_finding_count = findings['total_finding_count']
                    vuln_list.append(str(total_finding_count))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    fixed_finding_count = findings['fixed_finding_count']
                    vuln_list.append(str(fixed_finding_count))
                except (KeyError, IndexError, TypeError):
                    vuln_list.append(" ")

                try:
                    sensor_type = findings['sensor_type']
                    vuln_list.append(str(sensor_type))
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
