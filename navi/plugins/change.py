import click
from .api_wrapper import request_data


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


@click.command(help="Change Ownership")
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
