import click
from .api_wrapper import request_data
from .error_msg import error_msg
import pprint


@click.command(help="Interact with WAS V2 API")
@click.option('-scans', is_flag=True, help="Displays WAS Scans")
@click.option('--start', default='', help="Start Scan with Provided Scan ID")
@click.option('--sd', default='', help="Get Scan Details with Provided Scan ID")
def was(scans, start, sd):
    if scans:
        data = request_data('GET', '/was/v2/scans')
        try:
            for scan in data['data']:
                    app_url = scan['application_uri']
                    try:
                        scanner_used = scan['scanner']['group_name']
                    except:
                        scanner_used = scan['scanner']['name']

                    was_scan_id = scan['scan_id']
                    status = scan['status']
                    started = scan['started_at']
                    updated = scan['updated_at']

                    print("\n---Target URL/URI/Domain---")
                    print(app_url)
                    print("\nCurrent Status: " + status)
                    print("Scan ID : " + was_scan_id)
                    print("Scanner : " + scanner_used)
                    print("\nStarted: " + started)
                    print("Last Update: " + updated)
                    print("\n---Scan Data Available---\n")
                    try:
                        for i in scan['metadata']:
                            print(i, scan['metadata'][i])
                    except TypeError:
                        print("None Available")
                    print()
                    print("-" * 40)
                    print("-" * 40)

        except Exception as E:
            error_msg(E)

    if start != '':
        print("\n Your Scan is starting")

    if sd != '':
        querystring = {'size': 1000}
        data = request_data('GET', '/was/v2/scans/' + str(sd) + '/vulnerabilities', params=querystring)
        print("Plugin".ljust(10), "Plugin Name".ljust(60), "Severity".ljust(10), "CVSS3 Base Score".ljust(10))
        print("-" * 100)
        for i in data['data']:
            plugin_id = i['plugin_id']
            plugin_details = request_data('GET', '/was/v2/plugins/' + str(plugin_id))

            print(str(plugin_id).ljust(10), str(plugin_details['name']).ljust(60), str(plugin_details['risk_factor']).ljust(10), plugin_details['cvss3_base_score'])
