import click
from .api_wrapper import request_data
from .error_msg import error_msg
import time
import uuid
import csv
import textwrap
from .was_detailed_csv import was_detailed_export
from .was_v2_export import was_export


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
        "settings": {
            "target": str(target)
            }
        }
    )

    request_data('PUT', '/was/v2/configs/' + str(was_uuid), payload=payload)
    return


@click.group(help="Interact with WAS V2 API")
def was():
    pass


@was.command(help="Display All of the Completed Web Application Scans")
def scans():
    scan_params = {"size": "1000"}
    scans_data = request_data('GET', '/was/v2/scans', params=scan_params)
    click.echo("\n{:70s} {:40s} {:14s} {}".format("Target FQDN", "Scan UUID", "Status", "Last Update"))
    click.echo("-" * 150)
    try:
        for app_data in scans_data['data']:
            app_url = app_data['application_uri']
            app_scan_id = app_data['scan_id']
            app_status = app_data['status']
            updated = app_data['updated_at']

            click.echo("{:70s} {:40s} {:14s} {}".format(textwrap.shorten(str(app_url), width=70), str(app_scan_id), str(app_status), str(updated)))
        click.echo()
    except Exception as E:
        error_msg(E)


@was.command(help="Start a Web Application Scan")
@click.argument('scan_id')
def start(scan_id):
    click.echo("\n Your Scan is starting")
    request_data('POST', '/was/v2/configs/' + str(scan_id)+ '/scans')


@was.command(help="Display Details for Web Application Scan")
@click.argument('scan_id')
def details(scan_id):
    try:
        detail_report_data = request_data('GET', '/was/v2/scans/' + str(scan_id) + '/report')
        detail_high = []
        detail_meduim = []
        detail_low = []
        detail_name = detail_report_data['config']['name']
        try:
            detail_target = detail_report_data['scan']['target']
        except KeyError:
            detail_target = detail_report_data['config']['settings']['target']
        click.echo()
        click.echo(detail_name)
        click.echo(detail_target)
        click.echo("-" * 40)
        click.echo("\n{:10s} {:60s} {:10s} {:10s}".format("Plugin", "Plugin Name", "Severity", "CVSS"))
        click.echo("-" * 100)
        for detail_finding in detail_report_data['findings']:
            detail_risk = detail_finding['risk_factor']
            detail_plugin_id = detail_finding['plugin_id']
            plugin_name = detail_finding['name']
            cvss = 'None'
            if detail_risk == 'high':
                detail_high.append(detail_plugin_id)
            elif detail_risk == 'medium':
                detail_meduim.append(detail_plugin_id)
            elif detail_risk == 'low':
                detail_low.append(detail_plugin_id)
            try:
                cvss = detail_finding['cvss']
            except KeyError:
                pass
            click.echo("{:10s} {:60s} {:10s} {:10s}".format(str(detail_plugin_id), str(plugin_name), str(detail_risk),
                                                            str(cvss)))

        click.echo("\nSeverity Counts")
        click.echo("-" * 20)
        click.echo("High: {}".format(len(detail_high)))
        click.echo("Medium: {}".format(len(detail_meduim)))
        click.echo("Low: {}".format(len(detail_low)))
        click.echo()
    except KeyError:
        pass


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


@was.command(help="Display Web Application Configs")
def configs():
    params = {"size": "1000"}
    config_info = request_data('GET', '/was/v2/configs', params=params)
    click.echo("\n{:80s} {:40s} {}".format("Name", "Config ID", "Last Run"))
    click.echo("-" * 150)
    for config in config_info['data']:
        try:
            updated = config['last_scan']['updated_at']
        except TypeError:
            updated = "Not Run yet"
        click.echo("{:80s} {:40s} {}".format(textwrap.shorten(str(config['name']), width=80), str(config['config_id']), str(updated)))
    click.echo()


@was.command(help="Display Statistics for Web Application Scan")
@click.argument('scan_id')
def stats(scan_id):
    scan_metadata = request_data('GET', '/was/v2/scans/' + str(scan_id))
    report = request_data('GET', '/was/v2/scans/' + str(scan_id) + '/report')
    high = []
    medium = []
    low = []
    name = ''
    try:
        name = report['config']['name']
    except KeyError:
        print("Scan Did not Finish or your UUID is incorrect.")
        exit()
    try:
        target = report['scan']['target']
    except KeyError:
        target = report['config']['settings']['target']

    output = ''
    click.echo()
    click.echo(name)
    click.echo(target)
    click.echo("-" * 60)
    click.echo("\nNotes:")
    click.echo("-" * 60)
    for note in report['notes']:
        click.echo(note['title'])
        click.echo("\t- {}".format(note['message']))

    click.echo("\nScan Data Available")
    click.echo("-" * 40)

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

    click.echo("Requests Made: {}".format(requests_made))
    click.echo("Pages Crawled: {}".format(pages_crawled))
    click.echo("Pages Audited: {}".format(pages_audited))

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

    click.echo("\nSeverity Counts")
    click.echo("-"*20)
    click.echo("High: {}".format(len(high)))
    click.echo("Medium: {}".format(len(medium)))
    click.echo("Low: {}".format(len(low)))
    click.echo("\nScan Statistics")
    click.echo("-" * 20)
    click.echo(output)
    click.echo()


@was.command(help="Display a Summary of All of the WAS scans in Tenable.io")
def summary():
    # Grab all of the Scans
    params = {"size": "1000"}

    data = request_data('GET', '/was/v2/scans', params=params)
    click.echo("\n{:38s} {:40s} {:6s} {:6s} {:25s} {:20s}".format("Scan Name", "Target", "High", "Mid", "Low", "Scan Started", "Scan Finished"))
    click.echo("-" * 150)
    for scan_data in data['data']:
        was_scan_id = scan_data['scan_id']
        status = scan_data['status']
        summary_start = scan_data['started_at']
        finish = scan_data['finalized_at']

        # Ignore all scans that have not completed
        if status == 'completed':
            report = request_data('GET', '/was/v2/scans/' + was_scan_id + '/report')
            high = []
            medium = []
            low = []
            try:
                name = report['config']['name']
                try:
                    target = report['scan']['target']
                except KeyError:
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

                click.echo("{:38s} {:40s} {:6s} {:6s} {:25s} {:20s}".format(textwrap.shorten(str(name), width=38),
                                                                            textwrap.shorten(str(target), width=40),
                                                                            str(len(high)), str(len(medium)),
                                                                            str(len(low)), str(summary_start),
                                                                            str(finish)))
            except TypeError:
                pass
    click.echo()


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
