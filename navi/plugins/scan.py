import click
import textwrap
import time
from .scanners import nessus_scanners
from .api_wrapper import request_data, tenb_connection
from .error_msg import error_msg

tio = tenb_connection()


def get_scans_by_owner(owner):
    data = request_data('GET', '/scans')
    scan_data = []

    for get_scan in data['scans']:
        scan_id = get_scan['id']
        scan_owner = get_scan['owner']
        scan_name = get_scan['name']
        scan_uuid = get_scan['wizard_uuid']
        if scan_owner == owner:
            scan_data.append((scan_name, scan_id, owner, scan_uuid))
    return scan_data


def get_owner_uuid(owner):
    users = request_data('GET', '/users')
    user_uuid = 0

    for user in users['users']:
        if user['username'] == owner:
            user_uuid = user['id']
    return user_uuid


def get_targets(scan_id):
    get_scan_details = request_data('GET', '/scans/' + str(scan_id))
    try:
        targets = get_scan_details['info']['targets']
    except TypeError:
        targets = ""
    except KeyError:
        targets = ""

    try:
        tag_targets = get_scan_details['info']['tag_targets']
    except TypeError:
        tag_targets = ""

    scanner_name = get_scan_details['info']['scanner_name']

    return targets, tag_targets, scanner_name


def get_scanner_id(scan_name):
    scanners = request_data('GET', '/scanners')
    for scanner in scanners['scanners']:
        if scanner['name'] == scan_name:
            return scanner['id']


def scan_details(scan_id):
    try:
        data = request_data('GET', '/scans/' + str(scan_id))
        try:
            click.echo("\nScan Details for Scan ID : {}\n".format(scan_id))
            click.echo("Notes: \b")
            try:
                click.echo(data['notes'][0]['message'])
            except IndexError:
                pass
            click.echo("\nVulnerability Counts")
            click.echo("-" * 20)
            click.echo("Critical : {}".format(data['hosts'][0]['critical']))
            click.echo("high : {}".format(data['hosts'][0]['high']))
            click.echo("medium : {}".format(data['hosts'][0]['medium']))
            click.echo("low : {}".format(data['hosts'][0]['low']))
            try:
                click.echo("-" * 15)
                click.echo("Score : {}".format(data['hosts'][0]['score']))
            except IndexError:
                pass
            click.echo("\n{:10s} {:128s} {}".format("Plugin", "Vulnerability Details", "Vuln Count"))
            click.echo("-" * 150)

            for vulns in data['vulnerabilities']:
                if vulns['severity'] != 0:
                    click.echo("{:10s} {:128s} {}".format(str(vulns['plugin_id']), textwrap.shorten(str(vulns['plugin_name']), 128), vulns['count']))
            click.echo()
        except TypeError:
            click.echo("Check the scan ID")
    except Exception as E:
        click.echo("Check the scan ID\n")
        click.echo("Error: \n {}".format(E))
        exit()


def scan_hosts(scan_id):
    try:
        data = request_data('GET', '/scans/' + str(scan_id))

        try:
            click.echo("\nHosts Found by Scan ID : {}\n".format(scan_id))
            click.echo("{:20s} {:45s} {:10s} {:10s} {:10s} {:10s} ".format("IP Address", "UUID", "Critical", "High", "Medium", "Low"))
            click.echo("-"*150)
            for host in data['hosts']:

                click.echo("{:20s} {:45s} {:10s} {:10s} {:10s} {:10s}".format(host['hostname'], str(host['uuid']), str(host['critical']), str(host['high']), str(host['medium']), str(host['low'])))

            click.echo()
        except KeyError:
            click.echo("There was an Error.  It could be the scan was Aborted, canceled or Archived.\n")
            click.echo("Status: {}".format(data['info']['status']))
            click.echo("Archived? {}".format(data['info']['is_archived']))

        except TypeError:
            click.echo("Check the scan ID")
    except Exception as E:
        error_msg(E)


@click.group(help="Create and Control Scans")
def scan():
    pass


@scan.command(help="Quickly Scan a Target")
@click.argument('targets')
@click.option('--plugin', default='', help="Plugin required for Remediation Scan")
@click.option('--cred', default='', help="UUID of your intended credentials")
@click.option('-discovery', is_flag=True, help="Scan using the Discovery Template")
@click.option('--custom', default='', help="Scan using a custom Scan Template")
@click.option('--scanner', default='', help="Scanner ID")
@click.option('--policy', default='', help="Use Policy ID")
def create(targets, plugin, cred, discovery, custom, scanner, policy):
    # If a Template isn't chosen we will assume a Basic Network scan
    template = '731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65'

    if discovery:
        template = 'bbd4f805-3966-d464-b2d1-0079eb89d69708c3a05ec2812bcf'

    if len(custom) == 52:
        template = custom

    if scanner:
        scanner_id = scanner
    else:
        click.echo("Here are the available scanners")
        click.echo("Remember, don't pick a Cloud scanner for an internal IP address")
        click.echo("Remember also, don't chose a Webapp scanner for an IP address")
        nessus_scanners()
        scanner_id = input("What scanner do you want to scan with ?.... ")

    click.echo("creating your scan of : {}  Now...".format(targets))

    # Begin Payload Creation
    payload = dict(uuid=template,
                   settings={"name": "navi Created Scan of " + targets,
                             "enabled": "True",
                             "scanner_id": scanner_id,
                             "text_targets": targets})

    if cred:
        cred_data = request_data('GET', '/credentials/' + cred)
        try:
            cred_cat_name = cred_data['category']['name']
            cred_type_name = cred_data['type']['name']

            # Add credentials to payload
            payload["credentials"] = {"add": {cred_cat_name: {cred_type_name: [{"id": cred}]}}}

        except KeyError:
            click.echo("\nCheck your Credential UUID\n")
            exit()

    if policy:

        try:
            # Add policy to payload
            payload["settings"]["policy_id"] = policy

        except KeyError:
            click.echo("\nCheck your Credential UUID\n")
            exit()

    if plugin != '':
        advanced_template = 'ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66'

        # Change template
        payload["uuid"] = advanced_template

        # Add plugins to dictionary
        payload["enabled_plugins"] = [plugin]

    # create a new scan
    data = request_data('POST', '/scans', payload=payload)

    # pull scan ID after Creation
    scan_id = str(data["scan"]["id"])

    # launch Scan
    request_data('POST', '/scans/' + scan_id + '/launch')

    click.echo("I started your scan, your scan ID is: {}".format(scan_id))


@scan.command(help="Start a valid Scan")
@click.argument('scan_id')
def start(scan_id):
    tio.scans.launch(scan_id)


@scan.command(help="Get Scan Status")
@click.argument('Scan_id')
def status(scan_id):
    click.echo("\nLast Status update : {}\n".format(tio.scans.status(scan_id)))


@scan.command(help="Resume a paused Scan")
@click.argument('scan_id')
def resume(scan_id):
    tio.scans.resume(scan_id)


@scan.command(help="Pause a running Scan")
@click.argument('Scan_id')
def pause(scan_id):
    tio.scans.pause(scan_id)


@scan.command(help="Stop a Running Scan")
@click.argument('scan_id')
def stop(scan_id):
    tio.scans.stop(scan_id)


@scan.command(help="Change Ownership")
@click.option('--owner', default='', help='Current Owner login.')
@click.option('--new', default='', help='New Owner login.')
@click.option('--who', default='', help="Check what scans a user owns")
@click.option('-v', is_flag=True, help="Verbose output")
def change(owner, new, who, v):

    if who:
        who_scans = get_scans_by_owner(who)

        click.echo("\n{:80s} {:10} {}".format("Scan Name", "Scan ID", "Scan Owner"))
        click.echo("-" * 150)
        click.echo()

        for who_scan in who_scans:
            click.echo("{:80s} {:10} {}".format(str(who_scan[0]), str(who_scan[1]), str(who_scan[2])))
        click.echo()

    if owner:
        owner_scans = get_scans_by_owner(owner)
        new_owner_uuid = get_owner_uuid(new)

        click.echo("\n*** Scans that have not run, will produce HTTP 400 errors ***")
        click.echo("\nYou Scans are being converted now.")
        click.echo("\nThis can take some time")

        for owner_scan in owner_scans:
            scan_uuid = owner_scan[3]
            scan_name = owner_scan[0]
            scan_id = owner_scan[1]
            targets, tag_targets, scanner_name = get_targets(scan_id)
            payload = dict(uuid=scan_uuid, settings={"name": scan_name,
                                                     "owner_id": new_owner_uuid,
                                                     "tag_targets": tag_targets,
                                                     "text_targets": targets,
                                                     "scanner_id": get_scanner_id(scanner_name)
                                                     })

            request_data('PUT', '/scans/' + str(scan_id), payload=payload)
            if v:
                click.echo("\nDone - Payload: {}".format(str(payload)))


@scan.command(help="Display Scan Details")
@click.argument('scan_id')
def details(scan_id):
    scan_details(scan_id)


@scan.command(help="Display Hosts Found by a Scan ID")
@click.argument('scan_id')
def hosts(scan_id):
    scan_hosts(scan_id)


@scan.command(help="Display the Latest scan information")
def latest():
    try:
        data = request_data('GET', '/scans')
        time_list = []
        e = {}
        for x in data["scans"]:
            # keep UUID and Time together
            # get last modication date for duration computation
            epoch_time = x["last_modification_date"]
            # get the scanner ID to display the name of the scanner
            d = x["id"]
            # need to identify type to compare against pvs and agent scans
            scan_type = str(x["type"])
            # don't capture the PVS or Agent data in latest
            while scan_type not in ['pvs', 'agent', 'webapp', 'lce']:
                # put scans in a list to find the latest
                time_list.append(epoch_time)
                # put the time and id into a dictionary
                e[epoch_time] = d
                break

        # find the latest time
        grab_time = max(time_list)

        # get the scan with the corresponding ID
        grab_uuid = e[grab_time]

        # turn epoch time into something readable
        epock_latest = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(grab_time))
        click.echo("\nThe last Scan run was at {}".format(epock_latest))
        scan_details(str(grab_uuid))
    except Exception as E:
        error_msg(E)
