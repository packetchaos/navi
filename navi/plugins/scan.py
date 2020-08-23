import click
from .scanners import nessus_scanners
from .api_wrapper import request_data, tenb_connection
from .error_msg import error_msg

tio = tenb_connection()


def get_scans_by_owner(owner):
    data = request_data('GET', '/scans')
    scan_data = []
    for scan in data['scans']:
        scan_id = scan['id']
        scan_owner = scan['owner']
        scan_name = scan['name']
        scan_uuid = scan['wizard_uuid']
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
    scan_details = request_data('GET', '/scans/' + str(scan_id))
    try:
        targets = scan_details['info']['targets']
    except TypeError:
        targets = ""
    except KeyError:
        targets = ""

    try:
        tag_targets = scan_details['info']['tag_targets']
    except TypeError:
        tag_targets = ""

    scanner_name = scan_details['info']['scanner_name']

    return targets, tag_targets, scanner_name


def get_scanner_id(scan_name):
    scanners = request_data('GET', '/scanners')
    for scanner in scanners['scanners']:
        if scanner['name'] == scan_name:
            return scanner['id']



@click.group(help="Create and Control Scans")
def scan():
    pass


@scan.command(help="Quickly Scan a Target")
@click.argument('targets')
def create(targets):
    try:
        print("\nChoose your Scan Template")
        print("1.   Basic Network Scan")
        print("2.   Discovery Scan")
        print("3.   Web App Overview")
        print("4.   Web App Scan")
        print("5.   WAS SSL SCAN")
        option = input("Please enter option #.... ")
        if option == '1':
            template = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"
        elif option == '2':
            template = "bbd4f805-3966-d464-b2d1-0079eb89d69708c3a05ec2812bcf"
        elif option == '3':
            template = "58323412-d521-9482-2224-bdf5e2d65e6a4c67d33d4322677f"
        elif option == '4':
            template = "09805055-a034-4088-8986-aac5e1c57d5f0d44f09d736969bf"
        elif len(option) == 52:
            template = str(option)
        else:
            print("Using Basic scan since you can't follow directions")
            template = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"

        print("Here are the available scanners")
        print("Remember, don't pick a Cloud scanner for an internal IP address")
        print("Remember also, don't chose a Webapp scanner for an IP address")
        nessus_scanners()
        scanner_id = input("What scanner do you want to scan with ?.... ")

        print("creating your scan of : " + targets + "  Now...")

        payload = dict(uuid=template, settings={"name": "navi-Pro Created Scan of " + targets,
                                                "enabled": "True",
                                                "scanner_id": scanner_id,
                                                "text_targets": targets})

        # create a new scan
        data = request_data('POST', '/scans', payload=payload)

        # pull scan ID after Creation
        scan_id = str(data["scan"]["id"])

        # launch Scan
        request_data('POST', '/scans/' + scan_id + '/launch')

        print("I started your scan, your scan ID is: ", scan_id)

    except Exception as E:
        error_msg(E)


@scan.command(help="Start a valid Scan")
@click.argument('scan_id')
def start(scan_id):
    try:
        request_data('POST', '/scans/' + scan_id + '/launch')
    except:
        # Json error expected. Need to clean up api wrapper to fix this
        pass


@scan.command(help="Get Scan Status")
@click.argument('Scan_id')
def status(scan_id):
    try:
        data = request_data('GET', '/scans/'+str(scan_id) + '/latest-status')
        click.echo("\nLast Status update : {}".format(data['status']))
        click.echo()
    except Exception as E:
        error_msg(E)


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
        scans = get_scans_by_owner(who)

        print("\nScan Name".ljust(81), "Scan ID".ljust(10), "Scan Owner")
        print("-" * 150)
        print()
        for scan in scans:
            print(str(scan[0]).ljust(80), str(scan[1]).ljust(10), str(scan[2]))
        print()

    if owner:
        scans = get_scans_by_owner(owner)
        new_owner_uuid = get_owner_uuid(new)
        print("\n*** Scans that have not run, will produce HTTP 400 errors ***")
        print("\nYou Scans are being converted now.")
        print("\nThis can take some time")
        for scan in scans:
            scan_uuid = scan[3]
            scan_name = scan[0]
            scan_id = scan[1]
            targets, tag_targets, scanner_name = get_targets(scan_id)
            payload = dict(uuid=scan_uuid, settings={"name": scan_name,
                                                     "owner_id": new_owner_uuid,
                                                     "tag_targets": tag_targets,
                                                     "text_targets": targets,
                                                     "scanner_id": get_scanner_id(scanner_name)
                                                     })

            request_data('PUT', '/scans/' + str(scan_id), payload=payload)
            if v:
                print("\nDone - Payload: " + str(payload))
