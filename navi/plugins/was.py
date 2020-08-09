import click
from .api_wrapper import request_data
from .error_msg import error_msg
import time
import uuid
import csv
import textwrap


def web_app_scanners():
    print("\nHere are the available scanners")
    print("Remember, don't pick a Cloud scanner for an internal Site\n")
    scanners = request_data('GET', '/scanners')

    print("Scanner Name".ljust(30), "Scanner UUID")
    print("-" * 50)
    for scanner in scanners['scanners']:

        if str(scanner['supports_webapp']) == 'True':
            print(str(scanner['name']).ljust(29), str(scanner['id']))
    print()


def display_users():
    users = request_data('GET', '/users')
    print("\nUser Name".ljust(40), "User UUID")
    print("-" * 50)
    for user in users['users']:
        print(str(user['user_name'].ljust(39)), str(user['uuid']))
    print()


def create_was_scan(owner_id, temp_id, scanner_id, target, name):
    # use time to ensure UUID is correct
    uuid_offset = int(time.time())

    # create a new WAS UUID
    was_uuid = uuid.uuid1(uuid_offset)

    # Construct the payload
    payload = dict({
        "name": str(name),
        "owner_id": str(owner_id),
        "template_id": str(temp_id),
        "scanner_id": str(scanner_id),
        "settings": {
            "target": str(target)
            }
        }
    )

    request_data('PUT', '/was/v2/configs/' + str(was_uuid), payload=payload)


@click.command(help="Interact with WAS V2 API")
@click.option('-scans', is_flag=True, help="Displays WAS Scans")
@click.option('--start', default='', help="Start Scan with Provided Scan ID")
@click.option('--sd', default='', help="Get Scan Details with Provided Scan ID")
@click.option('--scan', default='', help="Create a scan via FQDN or CSV file name; use -file option for bulk scan creation via CSV file")
@click.option('-file', is_flag=True, help="File name of the CSV containing Web Apps for bulk scan creation")
@click.option('-configs', is_flag=True, help="Show config UUIDs to start or stop scans")
@click.option('--stats', default='', help="Show scan stats")
@click.option('-summary', is_flag=True, help="Summary of all of the Web Apps")
def was(scans, start, sd, scan, file, configs, stats, summary):
    if scans:
        params = {"size": "1000"}
        data = request_data('GET', '/was/v2/scans', params=params)
        print("\nTarget FQDN".ljust(70), "Scan UUID".ljust(40), "Status".ljust(14), "Last Update")
        print("-" * 150)
        try:
            for scan_data in data['data']:
                app_url = scan_data['application_uri']
                was_scan_id = scan_data['scan_id']
                status = scan_data['status']
                updated = scan_data['updated_at']

                print(textwrap.shorten(str(app_url), width=69).ljust(69), str(was_scan_id).ljust(40), str(status).ljust(14), str(updated))
            print()
        except Exception as E:
            error_msg(E)

    if start != '':
        print("\n Your Scan is starting")
        request_data('POST', '/was/v2/configs/' + start + '/scans')

    if sd != '':
        report = request_data('GET', '/was/v2/scans/' + str(sd) + '/report')
        high = []
        meduim = []
        low = []
        name = report['config']['name']
        target = report['config']['settings']['target']
        print()
        print(name)
        print(target)
        print("-" * 40)
        print()
        print("Plugin".ljust(10), "Plugin Name".ljust(60), "Severity".ljust(10), "CVSS".ljust(10))
        print("-" * 100)
        for finding in report['findings']:
            risk = finding['risk_factor']
            plugin_id = finding['plugin_id']
            plugin_name = finding['name']
            cvss = 'None'
            if risk == 'high':
                high.append(plugin_id)
            elif risk == 'medium':
                meduim.append(plugin_id)
            elif risk == 'low':
                low.append(plugin_id)
            try:
                cvss = finding['cvss']
            except KeyError:
                pass
            print(str(plugin_id).ljust(10), str(plugin_name).ljust(60), str(risk).ljust(10), str(cvss))

        print("\nSeverity Counts")
        print("-" * 20)
        print("High: ", len(high))
        print("Medium: ", len(meduim))
        print("Low: ", len(low))
        print()

    if scan:
        print("\nChoose your Scan Template")
        print("1.   Web App Overview")
        print("2.   Web App Scan")
        print("3.   WAS SSL SCAN")
        print("4.   WAS Config Scan")
        option = input("Please enter option #.... ")
        if option == '1':
            template = "b223f18e-5a94-4e02-b560-77a4a8246cd3"
        elif option == '2':
            template = "112f3e7f-d83a-4bba-b2c8-df2d22e2fa4c"
        elif option == '3':
            template = "072f4d6b-1dd7-4049-b279-78a56d1c778e"
        elif option == '4':
            template = "3078d0c6-6e81-44de-b585-6921b69ff0ef"
        elif len(option) == 36:
            template = str(option)
        else:
            print("Using Basic scan since you can't follow directions")
            template = "b223f18e-5a94-4e02-b560-77a4a8246cd3"

        # Display scanners
        web_app_scanners()

        # Capture Scanner selection
        scanner_id = input("What scanner do you want to scan with ?.... ")

        # Display Users UUID
        display_users()
        # Capture User UUID selection
        user_uuid = input("Select an Scan owner using the UUID ?.... ")

        scan_name = "navi Created Scan of : " + str(scan)

        if file:
            with open(scan, 'r', newline='') as csv_file:
                web_apps = csv.reader(csv_file)
                for apps in web_apps:
                    for app in apps:
                        scan_name = "navi Created Scan of : " + str(app)
                        create_was_scan(owner_id=user_uuid, scanner_id=scanner_id, name=scan_name, temp_id=template, target=str(app))
                        time.sleep(5)
        else:
            print("\nCreating your scan now for site: " + str(scan))
            create_was_scan(owner_id=user_uuid, scanner_id=scanner_id, name=scan_name, temp_id=template, target=scan)

    if configs:
        params = {"size": "1000"}
        config_info = request_data('GET', '/was/v2/configs', params=params)
        print("Name".ljust(80), "Config ID".ljust(40), "Last Run")
        print("-" * 150)
        for config in config_info['data']:
            try:
                updated = config['last_scan']['updated_at']
            except TypeError:
                updated = "Not Run yet"
            print(textwrap.shorten(str(config['name']), width=80).ljust(80), str(config['config_id']).ljust(40), str(updated))
        print()

    if stats:
        scan_metadata = request_data('GET', '/was/v2/scans/' + str(stats))
        report = request_data('GET', '/was/v2/scans/' + str(stats) + '/report')
        high = []
        medium = []
        low = []
        name = report['config']['name']
        target = report['config']['settings']['target']
        output = ''
        print()
        print(name)
        print(target)
        print("-" * 60)
        print("\nNotes:")
        print("-" * 60)
        for note in report['notes']:
            print(note['title'])
            print("\t- ", note['message'])

        print("\nScan Data Available")
        print("-" * 40)

        try:
            for i in scan_metadata['metadata']:
                print(i, scan_metadata['metadata'][i])
        except TypeError:
            print("None Available")

        for finding in report['findings']:
            risk = finding['risk_factor']
            plugin_id = finding['plugin_id']

            if plugin_id == 98000:
                output = finding['output']

            if risk == 'high':
                high.append(plugin_id)
            elif risk == 'medium':
                medium.append(plugin_id)
            elif risk == 'low':
                low.append(plugin_id)

        print("\nSeverity Counts")
        print("-"*20)
        print("High: ", len(high))
        print("Medium: ", len(medium))
        print("Low: ", len(low))
        print("\nScan Statistics")
        print("-" * 20)
        print(output)
        print()

    if summary:
        # Grab all of the Scans
        params = {"size": "1000"}

        data = request_data('GET', '/was/v2/scans', params=params)
        print("\nScan Name".ljust(38), "Target".ljust(40), "High".ljust(6), "Mid".ljust(6), "Low".ljust(6), "Scan Started".ljust(25), "Scan Finished".ljust(20))
        print("-" * 150)
        for scan_data in data['data']:
            was_scan_id = scan_data['scan_id']
            status = scan_data['status']
            start = scan_data['started_at']
            finish = scan_data['finalized_at']

            # Ignore all scans that have not completed
            if status == 'completed':
                report = request_data('GET', '/was/v2/scans/' + was_scan_id + '/report')
                high = []
                medium = []
                low = []
                try:
                    name = report['config']['name']
                    target = report['config']['settings']['target']

                    for finding in report['findings']:
                        risk = finding['risk_factor']
                        plugin_id = finding['plugin_id']
                        if risk == 'high':
                            high.append(plugin_id)
                        elif risk == 'medium':
                            medium.append(plugin_id)
                        elif risk == 'low':
                            low.append(plugin_id)

                    print(textwrap.shorten(str(name), width=37).ljust(37), textwrap.shorten(str(target), width=40).ljust(40), str(len(high)).ljust(6), str(len(medium)).ljust(6), str(len(low)).ljust(6), str(start).ljust(25), str(finish))
                except TypeError:
                    pass
        print()
