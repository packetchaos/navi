import click
from .api_wrapper import request_data, tenb_connection
import time
import uuid
import csv
import textwrap
from .database import db_query


tio = tenb_connection()


def web_app_scanners():
    click.echo("\nHere are the available scanners")
    click.echo("Remember, don't pick a Cloud scanner for an internal Site\n")
    scanners = request_data('GET', '/scanners')

    click.echo("{:30s} {}".format("Scanner Name", "Scanner UUID"))
    click.echo("-" * 50)
    for scanner in scanners['scanners']:
        if str(scanner['supports_webapp']) == 'True':
            click.echo("{:30s} {}".format(str(scanner['name']), str(scanner['id'])))
    click.echo()


def display_users():
    users = request_data('GET', '/users')
    click.echo("\n{:40s} {}".format("User Name", "User UUID"))
    click.echo("-" * 50)
    for user in users['users']:
        click.echo("{:40s} {}".format(str(user['user_name']), str(user['uuid'])))
    click.echo()


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
        "target": str(target)
        }
    )

    request_data('PUT', '/was/v2/configs/' + str(was_uuid), payload=payload)
    return


@click.group(help="Interact with WAS V2 API")
def was():
    pass


@was.command(help="[STEP TWO] - Display Scan IDs for a given Scan Config")
@click.argument('config_uuid')
def scans(config_uuid):
    params = {"limit": "200", "offset": "0"}
    was_data = request_data("POST", "/was/v2/configs/{}/scans/search".format(config_uuid), params=params)

    click.echo("\n{:70s} {:15s} {:15s} {:40} {}".format("Target FQDN", "Audited URLS", "Found URLS", "Scan_ID", "Status"))
    click.echo("-" * 150)
    for app_data in was_data['items']:

        app_url = app_data['application_uri']
        app_scan_id = app_data['scan_id']
        try:
            app_audited_urls = app_data['metadata']['audited_urls']
        except TypeError:
            app_audited_urls = 0
        except KeyError:
            app_audited_urls = 0
        try:
            app_found_urls = app_data['metadata']['found_urls']
        except TypeError:
            app_found_urls = 0
        except KeyError:
            app_found_urls = 0
        try:
            app_status = app_data['status']
        except KeyError:
            app_status = "None"
        try:
            updated = app_data['updated_at']
        except KeyError:
            updated = "None"

        click.echo("{:70s} {:15s} {:15s} {:40} {}".format(textwrap.shorten(str(app_url), width=70), str(app_audited_urls), str(app_found_urls), str(app_scan_id), str(app_status), str(updated)))

    click.echo()


@was.command(help="Start a Web Application Scan")
@click.argument('scan_id')
def start(scan_id):
    click.echo("\n Your Scan is starting")
    request_data('POST', '/was/v2/configs/' + str(scan_id) + '/scans')


@was.command(help=" [STEP THREE] - Display Details for a Web Application Scan")
@click.argument('scan_uuid')
@click.option('--plugin', default='', help="Get Plugin output, response headers and request headers")
def details(scan_uuid, plugin):

    if plugin:
        plugin_data = db_query("select payload, output, request_headers, response_headers, description, solution, cves from plugins where scan_uuid='{}' and plugin_id='{}'".format(scan_uuid, plugin))

        click.echo("Description")
        click.echo("-" * 35)
        click.echo()
        click.echo(plugin_data[0][4])
        click.echo()
        click.echo("Payload")
        click.echo("-" * 35)
        click.echo()
        click.echo(plugin_data[0][0])
        click.echo()
        click.echo("Request Headers")
        click.echo("-" * 35)
        click.echo()
        click.echo(plugin_data[0][2])
        click.echo()
        click.echo("Response Headers")
        click.echo("-" * 35)
        click.echo()
        click.echo(plugin_data[0][3])
        click.echo()
        click.echo("Output")
        click.echo("-" * 35)
        click.echo()
        click.echo(plugin_data[0][1])
        click.echo()
        click.echo("Solution")
        click.echo("-" * 35)
        click.echo()
        click.echo(plugin_data[0][5])
        click.echo()
        click.echo("CVEs")
        click.echo("-" * 35)
        click.echo()
        click.echo(plugin_data[0][6])
        click.echo()

    else:
        detail_report_data = db_query("select * from plugins where scan_uuid='{}'".format(scan_uuid))
        detail_high = []
        detail_meduim = []
        detail_low = []
        click.echo("-" * 40)
        click.echo("\n{:10s} {:60s} {:10}".format("Plugin", "Plugin Name", "Severity"))
        click.echo("-" * 150)
        for detail_finding in detail_report_data:
            detail_plugin_id = detail_finding[8]
            detail_risk = detail_finding[14]
            plugin_name = detail_finding[1]

            if detail_risk == 'high':
                detail_high.append(detail_plugin_id)
            elif detail_risk == 'medium':
                detail_meduim.append(detail_plugin_id)
            elif detail_risk == 'low':
                detail_low.append(detail_plugin_id)

            click.echo("{:10s} {:60s} {:10} ".format(str(detail_plugin_id), textwrap.shorten(str(plugin_name), width=60),
                                                 str(detail_risk)))

        click.echo("\nSeverity Counts")
        click.echo("-" * 20)
        click.echo("High: {}".format(len(detail_high)))
        click.echo("Medium: {}".format(len(detail_meduim)))
        click.echo("Low: {}".format(len(detail_low)))
        click.echo()


@was.command(help="Scan a Web Application Target")
@click.argument('scan_target')
@click.option('--file', is_flag=True, help="File name of the CSV containing Web Apps for bulk scan creation")
def scan(scan_target, file):
    click.echo("\nChoose your Scan Template")
    click.echo("1.   Web App Overview")
    click.echo("2.   Web App Scan")
    click.echo("3.   WAS SSL SCAN")
    click.echo("4.   WAS Config Scan")
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
        click.echo("Using Basic scan since you can't follow directions")
        template = "b223f18e-5a94-4e02-b560-77a4a8246cd3"

    # Display scanners
    web_app_scanners()

    # Capture Scanner selection
    scanner_id = input("What scanner do you want to scan with ?.... ")

    # Display Users UUID
    display_users()
    # Capture User UUID selection
    user_uuid = input("Select an Scan owner using the UUID ?.... ")

    scan_name = "navi Created Scan of : " + str(scan_target)

    if file:
        with open(scan_target, 'r', newline='') as csv_file:
            web_apps = csv.reader(csv_file)
            for apps in web_apps:
                for app in apps:
                    scan_name = "navi Created Scan of : " + str(app)
                    # strip for white spaces
                    application = app.strip()
                    create_was_scan(owner_id=user_uuid, scanner_id=scanner_id, name=scan_name, temp_id=template, target=application)
                    time.sleep(2)
    else:
        click.echo("\nCreating your scan now for site: " + str(scan_target))
        create_was_scan(owner_id=user_uuid, scanner_id=scanner_id, name=scan_name, temp_id=template, target=scan_target)


@was.command(help="[STEP ONE] - Display Web Application Configs")
def configs():
    # This doesn't hit the database to provide visibility in to all status' not just completed
    params = {"limit": "200", "offset": "0"}
    was_data = request_data("POST", "/was/v2/configs/search", params=params)

    click.echo("\n{:70s} {:40s} {:14s} {}".format("Config Name", "Config ID", "Status", "Last Update"))
    click.echo("-" * 150)
    for app_data in was_data['items']:
        try:
            app_name = app_data['name']
            app_scan_id = app_data['config_id']
            app_status = app_data['last_scan']['status']
            updated = app_data['updated_at']

            click.echo("{:70s} {:40s} {:14s} {}".format(textwrap.shorten(str(app_name), width=70), str(app_scan_id), str(app_status), str(updated)))
        except:
            pass
    click.echo()


@was.command(help="Display Statistics for Web Application Scan")
@click.argument('scan_id')
def stats(scan_id):
    params = {"limit": "200", "offset": "0"}
    was_data = request_data("POST", "/was/v2/scans/{}/vulnerabilities/search".format(scan_id), params=params)

    for finding in was_data['items']:
        if str(finding['plugin_id']) == '98000':

            scan_meta_data = finding['details']['output']
            print(scan_meta_data)

'''
@was.command(help="CSV Export")
@click.confirmation_option(prompt='\nThis is going to export all of your data into a CSV. It will take some time')
@click.option("-d", is_flag=True, help="Export most of the Plugin Data for all applications into a csv")
@click.option("-s", is_flag=True, help="Export Summary data for all applications into a csv")
def export(d, s):
    if d:
        was_detailed_export()
    if s:
        was_export()

    if not s and not d:
        click.echo("\nYou must specify a selection use -d for Detailed and -s for summary\n")
'''
