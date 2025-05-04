from sqlite3 import Error
import time
import arrow
from .api_wrapper import tenb_connection, navi_version, request_data
from .database import new_db_connection, db_query
from .fixed_export import print_sla
import click
import pprint
import textwrap
from .error_msg import error_msg


tio = tenb_connection()


def display_stats():
    try:
        total = db_query("select count(software_string) from software;")[0][0]
        asset_total = db_query("select count(distinct asset_uuid) from vulns;")[0][0]
        assets_with_data = db_query("select count(distinct asset_uuid) from vulns "
                                    "where plugin_id ='22869' or plugin_id ='20811';")[0][0]
        assets_without_data = db_query("select hostname, uuid, ip_address from assets where  ip_address !=' ' and "
                                       "uuid not in (select distinct asset_uuid from vulns "
                                       "where plugin_id ='22869' or plugin_id ='20811')")

        click.echo("\nUnique Software total is: " + str(total))
        click.echo("\nAssets evaluated: " + str(asset_total))
        click.echo("\nAssets with Software: " + str(assets_with_data))
        click.echo("\nAssets Without Software Plugins: " + str(len(assets_without_data)))
        click.echo()
    except:
        click.echo("\nYou need to run 'navi software generate' to populate the software table.\n")


def get_licensed():
    data = request_data('GET', '/workbenches/asset-stats?date_range=90&filter.0.filter=is_licensed&filter.0.quality=eq&filter.0.value=true')
    number_of_assets = data['scanned']
    return number_of_assets


def get_scanners():
    try:
        click.echo("\n{:35s} {:20} {}".format("Scanner Name", "Scanner ID", "Scanner UUID"))
        click.echo("-" * 150)
        for nessus in tio.scanners.list():
            click.echo("{:35s} {:20} {}".format(str(nessus["name"]), str(nessus["id"]), str(nessus['uuid'])))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


def compare_dates(given_date):
    today = arrow.now()
    try:
        given_date = arrow.get(given_date)
        days_difference = (today - given_date).days

        if days_difference > 35:
            return "no"
        else:
            return "yes"
    except ValueError:
        print("Invalid date format")


@click.group(help="Explore Asset details, query the Navi Database and explore the API")
def explore():
    pass


@explore.group(help="Display all information found in Tenable vulnerability management: "
                    "users, scanners, exclusions, agents, tags, exports, networks, permissions, policies,"
                    "templates, sla, software, polices, scans, connectors, etc")
def info():
    pass


@info.command(help="Display all of the scanners")
def scanners():
    get_scanners()


@info.command(help="Display  all of the Users")
def users():
    try:
        click.echo("\n{:34s} {:40s} {:40s} {:10s} {}".format("User Name", "Login Email", "UUID", "ID", "Enabled"))
        click.echo("-" * 150)
        for user in tio.users.list():
            click.echo("{:34s} {:40s} {:40s} {:10s} {}".format(str(user["user_name"]), str(user["username"]),
                                                               str(user['uuid']), str(user['id']),
                                                               str(user['enabled'])))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display all Exclusions")
def exclusions():
    try:
        for exclusion in tio.exclusions.list():
            click.echo("\n{} {}".format("Exclusion Name :", exclusion["name"]))
            click.echo("-" * 150)
            click.echo("{}".format(str(exclusion["members"])))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display The actor and the action in the log file")
def logs():
    try:
        events = tio.audit_log.events()
        click.echo("{:24s} {:30s} {}".format("Event Date", "Action Taken", "User"))
        click.echo("-" * 150)

        for log in events:
            click.echo("{:24s} {:30s} {:30s}".format(str(log['received']), str(log['action']),
                                                     str(log['actor']['name'])))

        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display running Scans")
def running():
    try:
        click.echo("\n{:60s} {:10s} {:30s}".format("Scan Name", "Scan ID", "Status"))
        click.echo("-" * 150)

        for scan in tio.scans.list():
            if scan['status'] == "running":
                click.echo("{:60s} {:10s} {:30s}".format(str(scan['name']), str(scan['id']), str(scan['status'])))

        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Scans")
@click.option("-a", is_flag=True, help="Display all scans")
def scans(a):
    try:
        click.echo("\n{:80s} {:5s} {:10s} {:40}".format("Scan Name", "ID", "Status", "UUID"))
        click.echo("-" * 150)

        if a:
            for scan in tio.scans.list():
                    try:
                        click.echo("{:80s} {:5s} {:10s} {:40}".format(textwrap.shorten(str(scan['name']), width=80), str(scan['id']), str(scan['status']),
                                                                    str(scan['uuid'])))
                    except KeyError:
                        click.echo("{:80s} {:5s} {:10s} {:40}".format(textwrap.shorten(str(scan['name']), width=80), str(scan['id']), str(scan['status']),
                                                                    "No UUID"))
        else:
            for scan in tio.scans.list():
                if str(compare_dates(scan['last_modification_date'])) == 'yes':
                    try:
                        click.echo("{:80s} {:5s} {:10s} {:40}".format(textwrap.shorten(str(scan['name']), width=80), str(scan['id']), str(scan['status']),
                                                                    str(scan['uuid'])))
                    except KeyError:
                        click.echo("{:80s} {:5s} {:10s} {:40}".format(textwrap.shorten(str(scan['name']), width=80), str(scan['id']), str(scan['status']),
                                                                    "No UUID"))
                else:
                    pass
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display NNM assets and their vulnerability scores")
def nnm():
    click.echo("\nChecking all NNM scanners for assets recently found...")
    click.echo("\n{:20} {:10} {}".format("IP Address", "Score", "Scan ID"))
    click.echo("-" * 150)

    for scan in tio.scans.list():
        try:
            if str(scan["type"]) == "pvs":
                resp = tio.get('scans/{}'.format(scan["id"]))
                data = resp.json()

                for host in data["hosts"]:
                    click.echo("{:20} {:10} {}".format(str(host["hostname"]), str(host["score"]), str(scan["id"])))

        except AttributeError:
            click.echo("\nCheck your permissions or your API keys\n")

        except KeyError:
            pass


@info.command(help="Display All Assets found in the last 30 days")
@click.option("--tag", default='', help="Display Assets membership of a given Tag.  "
                                        "Use Tag Value UUID found in the command 'navi display tags'")
@click.option("--net", default='', required=True, help="Select Network ID")
def assets(tag, net):
    if tag:
        data = db_query("select ip_address, fqdn, aes, acr from assets "
                        "LEFT JOIN tags ON uuid == asset_uuid where tag_uuid=='{}';".format(tag))

        click.echo("\nBelow are the assets that are apart of the Tag")
        click.echo("\n{:16} {:80} {:6} {}".format("IP Address", "FQDN", "AES", "ACR"))
        click.echo("-" * 150)
        try:
            for asset in data:
                ipv4 = str(asset[0])
                fqdn = str(asset[1])
                exposure_score = str(asset[2])
                acr = str(asset[3])

                click.echo("{:16} {:80} {:6} {}".format(ipv4, textwrap.shorten(fqdn, width=80),
                                                        exposure_score, acr))
            click.echo()
        except TypeError:
            click.echo("\nThe Tag has no assets or the tag hasn't finished being processed by T.io\n")
    elif net:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT ip_address, fqdn, last_licensed_scan_date from assets where network == '" + net + "';")
            data = cur.fetchall()

            click.echo("\n{:25s} {:65s} {}".format("IP Address", "Full Qualified Domain Name", "Licensed Scan Date"))
            click.echo("-" * 150)
            click.echo()

            for asset in data:
                ipv4 = asset[0]
                fqdn = asset[1]
                licensed_date = asset[2]

                click.echo("{:25s} {:65s} {}".format(str(ipv4), str(fqdn), licensed_date))

        click.echo()
    else:
        try:
            click.echo("\nBelow are the assets found in the last 30 days")
            click.echo("\n{:16} {:80} {:40} {:6}".format("IP Address", "FQDN", "UUID", "AES"))
            click.echo("-" * 150)
            asset_data = db_query("select ip_address, fqdn, uuid, aes from assets;")
            for asset in asset_data:

                click.echo("{:16} {:80} {:40} {:6} ".format(asset[0],
                                                            textwrap.shorten(asset[1], width=80), asset[2],
                                                            str(asset[3])))

            click.echo("\nTotal: {}\n\n".format(len(asset_data)))
        except AttributeError:
            click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Scan Policies")
def policies():
    try:
        click.echo("\n{:40s} {:51s} {:10} {}".format("Policy Name", "Description", "ID", "Template ID"))
        click.echo("-" * 150)

        for policy in tio.policies.list():
            click.echo("{:40s} {:51s} {:10} {}".format(textwrap.shorten(str(policy['name']),
                                                                        width=40),
                                                       textwrap.shorten(str(policy['description']),
                                                                        width=51), str(policy['id']),
                                                       policy['template_uuid']))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Cloud Connector Details and Status")
def connectors():
    try:
        resp = tio.get('settings/connectors')
        data = resp.json()

        click.echo("\n{:11s} {:40s} {:40s} {:30s} {}".format("Type", "Connector Name",
                                                             "Connector ID", "Last Sync", "Schedule"))
        click.echo("-" * 150)
        schedule = "None"
        for conn in data["connectors"]:
            try:
                schedule = str(conn['schedule']['value']) + " " + str(conn['schedule']['units'])

                last_sync = conn['last_sync_time']
            except KeyError:
                last_sync = "Hasn't synced"

            click.echo("{:11s} {:40s} {:40s} {:30s} {}".format(str(conn['type']), str(conn['name']),
                                                               str(conn['id']), last_sync, schedule))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display T.io Status and Account info")
def status():
    try:
        data = tio.server.properties()
        session_data = tio.session.details()
        click.echo("\nTenable IO Information")
        click.echo("-" * 25)
        click.echo("{} {}".format("Container ID : ", session_data["container_id"]))
        click.echo("{} {}".format("Container UUID :", session_data["container_uuid"]))
        click.echo("{} {}".format("Container Name : ", session_data["container_name"]))
        click.echo("{} {}".format("Site ID :", data["analytics"]["site_id"]))
        click.echo("{} {}".format("Region : ", data["region"]))

        click.echo("\nLicense information")
        click.echo("-" * 25)
        click.echo("{} {}".format("Licensed Assets : ", get_licensed()))
        click.echo("{} {}".format("Agents Used : ", data['license']["agents"]))
        try:
            click.echo("{} {}".format("Expiration Date : ", data['license']["expiration_date"]))
        except KeyError:
            pass
        click.echo("{} {}".format("Scanners Used : ", data['license']["scanners"]))
        click.echo("{} {}".format("Users : ", data["license"]["users"]))

        click.echo("\nEnabled Apps")
        click.echo("-" * 15)
        click.echo()
        try:
            for key in data["license"]["apps"]:
                click.echo(key)
                click.echo("-" * 5)
                try:
                    click.echo("{} {}".format("Expiration: ",
                                              str(data["license"]["apps"][key]["expiration_date"])))
                except KeyError:
                    pass
                click.echo("{} {}".format("Mode: ", str(data["license"]["apps"][key]["mode"])))
                click.echo()
        except KeyError:
            pass

    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Agent information - Limit 5000 agents")
@click.option("-uuid", is_flag=True, help="Display Agent information including Agent UUID")
def agents(uuid):
    try:
        if uuid:
            click.echo("\n{:30s} {:20} {:20} {:20} {:6} {}".format("Agent Name", "IP Address",
                                                                   "Last Connect Time",
                                                                   "Last Scanned Time", "Status", "UUID"))
            click.echo("-" * 150)
        else:
            click.echo("\n{:30s} {:20} {:20} {:20} {:6} {}".format("Agent Name", "IP Address",
                                                                   "Last Connect Time", "Last Scanned Time",
                                                                   "Status", "Group(id)s"))
            click.echo("-" * 150)

        for agent in tio.agents.list():
            try:
                last_connect = agent['last_connect']
                last_connect_time = time.strftime("%b %d %H:%M:%S", time.localtime(last_connect))
            except KeyError:
                last_connect_time = "Unknown"

            try:
                last_scanned = agent['last_scanned']
                last_scanned_time = time.strftime("%b %d %H:%M:%S", time.localtime(last_scanned))
            except KeyError:
                # I assume if we can't pull as scanned time, it doesn't exist
                last_scanned_time = "Not Scanned"
            groups = ''
            try:
                for group in agent['groups']:
                    groups = groups + ", {}({})".format(group['name'], group['id'])
            except KeyError:
                pass

            try:
                agent_uuid = agent['uuid']
            except KeyError:
                agent_uuid = "unknown"

            if uuid:
                click.echo("{:30s} {:20s} {:20s} {:20s} {:6s} {}".format(textwrap.shorten(str(agent['name']),
                                                                                          width=30),
                                                                         str(agent['ip']), str(last_connect_time),
                                                                         str(last_scanned_time), str(agent['status']),
                                                                         textwrap.shorten(agent_uuid, width=60)))
            else:
                click.echo("{:30s} {:20s} {:20s} {:20s} {:6s} {}".format(textwrap.shorten(str(agent['name']),
                                                                                          width=30),
                                                                         str(agent['ip']), str(last_connect_time),
                                                                         str(last_scanned_time), str(agent['status']),
                                                                         textwrap.shorten(groups[1:], width=60)))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Target Groups")
def tgroups():
    try:
        print("\nTarget Group Name".ljust(41), "TG ID".ljust(10), "Owner".ljust(30), "Members")
        print("-" * 100)
        for targets in tio.target_groups.list():
            mem = targets['members']
            print(str(targets['name']).ljust(40), str(targets['id']).ljust(10), str(targets['owner']).ljust(30),
                  textwrap.shorten(mem, width=60))
        print()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Licensed Assets")
def licensed():
    try:
        click.echo("\n{} {}".format("Licensed Count: ", get_licensed()))
        click.echo()
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT uuid, fqdn, last_licensed_scan_date from assets where last_licensed_scan_date !=' ';")
            data = cur.fetchall()

            click.echo("{:40s} {:65s} {}".format("Asset UUID", "Full Qualified Domain Name", "Licensed Date"))
            click.echo("-" * 150)
            click.echo()
            count = 0
            for asset in data:
                count += 1
                uuid = asset[0]
                fqdn = asset[1]
                licensed_date = asset[2]
                click.echo("{:40s} {:65s} {}".format(str(uuid), str(fqdn), licensed_date))
        click.echo("\nTotal: {}".format(count))
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Tags Information")
def tags():
    try:
        click.echo("\n{:55s} {:55s} {}".format("Category", "  Value", "  Value UUID"))
        click.echo("-" * 150)
        for tag_values in tio.tags.list():
            try:
                tag_value = tag_values['value']
                uuid = tag_values['uuid']
            except KeyError:
                tag_value = "Value Not Set Yet"
                uuid = "NO Value set"
            click.echo("{:55s} : {:55s} {}".format(textwrap.shorten(str(tag_values['category_name']), width=55),
                                                   textwrap.shorten(str(tag_value), width=55),
                                                   str(uuid)))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Tag Categories and UUIDs")
def categories():
    try:
        click.echo("\n{:31s} {}".format("Tag Categories", "Category UUID"))
        click.echo("-" * 150)
        for cats in tio.tags.list_categories():
            category_name = cats['name']
            category_uuid = cats['uuid']
            click.echo("{:31s} {}".format(str(category_name), str(category_uuid)))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Network Information including scanner counts")
def networks():
    try:
        click.echo("\n{:45s} {:16} {}".format("Network Name", "# of Scanners", "UUID"))
        click.echo("-" * 150)

        for network in tio.networks.list():
            click.echo("{:45s} {:16} {}".format(str(network['name']), str(network['scanner_count']),
                                                str(network['uuid'])))
        click.echo()

    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display the current Navi Version")
def version():
    click.echo("\nCurrent Navi Version: {}\n".format(navi_version()))


@info.command(help="Display User group information")
@click.option('--membership', required=True, default='', help="Display Users that apart of a particular "
                                                              "user group using the user group ID")
def usergroups(membership):
    try:
        if membership:
            click.echo("\n{:35s} {:40s} {:40s} {:10} {}".format("User Name", "Login email", "User UUID", "User ID",
                                                                "Enabled?"))
            click.echo("-" * 150)
            for user in tio.groups.list_users(membership):
                click.echo("{:35s} {:40s} {:40s} {:10} {}".format(str(user["name"]), str(user["username"]),
                                                                  str(user['uuid']), str(user['id']),
                                                                  str(user["enabled"])))
            click.echo()
        else:
            click.echo("\n{:35s} {:10s} {:40s} {}".format("Group Name", "Group ID", "Group UUID", "User Count"))
            click.echo("-" * 150)

            for user_group in tio.groups.list():
                click.echo("{:35s} {:10s} {:40s} {}".format(str(user_group['name']), str(user_group['id']),
                                                            str(user_group['uuid']), str(user_group['user_count'])))
            click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display All Credentials, including Type and Credential UUID")
def credentials():
    try:

        click.echo("\n{:25s} {:25s} {:25s} {:25s} {:40s}".format("Credential Name", "Created By",
                                                                 "Credential Type", "Category", "Credential UUID"))
        click.echo("-" * 150)

        for cred in tio.credentials.list():
            creator = cred['created_by']['display_name']
            name = cred['name']
            cred_type = cred['type']['name']
            cred_uuid = cred['uuid']
            category = cred['category']['name']
            click.echo("{:25s} {:25s} {:25s} {:25s} {:40s}".format(textwrap.shorten(name, width=25),
                                                                   textwrap.shorten(creator, width=25),
                                                                   textwrap.shorten(cred_type, width=25),
                                                                   textwrap.shorten(category, width=25),
                                                                   textwrap.shorten(cred_uuid, width=40)))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display Asset and Vulnerability Export Job information")
@click.option('-a', help="Display Asset Export Jobs", is_flag=True)
@click.option('-v', help="Display Vulnerability Export Jobs", is_flag=True)
def exports(a, v):
    if not a and not v:
        click.echo("\nYou need to use '-a' or '-v' to select your export type. (assets vs vulns)\n")

    current_time = time.time()
    time_frame = (current_time - (86400 * 3)) * 1000
    if a:
        export_data = request_data('GET', '/assets/export/status')
        click.echo("{:45s} {:20s} {:10s} {:45s} {:10s} {}".format("\nAsset Export UUID", "Created Date", "Status",
                                                                  "Export Filter Used",  "Chunk Size", "Total Chunks"))
        click.echo('-' * 150)

        for export in export_data['exports']:
            compare_time = export['created']
            newtime = arrow.Arrow.fromtimestamp(compare_time)

            if compare_time > time_frame:
                export_uuid = export['uuid']
                export_status = export['status']
                export_chunk_size = export['num_assets_per_chunk']
                export_filter = export['filters']
                export_total_chunks = export['total_chunks']

                click.echo("{:44s} {:20s} {:10s} {:45s} {:10d} {}".format(export_uuid,
                                                                          newtime.format('MM-DD-YYYY'),
                                                                          export_status, export_filter,
                                                                          export_chunk_size, export_total_chunks))

    if v:
        vuln_export_data = request_data('GET', '/vulns/export/status')
        click.echo("{:45s} {:20s} {:10s} {:45s} {:10s} {}".format("\nVulnerability Export UUID", "Created Date",
                                                                  "Status", "States", "Chunk Size", "Total Chunks"))
        click.echo('-' * 150)

        for vuln_export in vuln_export_data['exports']:
            vuln_compare_time = vuln_export['created']
            vuln_newtime = arrow.Arrow.fromtimestamp(vuln_compare_time)

            if vuln_compare_time > time_frame:
                export_uuid = vuln_export['uuid']
                export_status = vuln_export['status']
                export_chunk_size = vuln_export['num_assets_per_chunk']
                export_filter = str(vuln_export['filters']['state'])
                vuln_export_total_chunks = vuln_export['total_chunks']

                click.echo("{:44s} {:20s} {:10s} {:45s} {:10d} {}".format(export_uuid,
                                                                          vuln_newtime.format('MM-DD-YYYY'),
                                                                          export_status, export_filter,
                                                                          export_chunk_size, vuln_export_total_chunks))

    click.echo()


@info.command(help="Display Authorization information for a user given a User ID")
@click.argument('uid')
def auth(uid):
    info = request_data("GET", "/users/{}/authorizations".format(uid))

    click.echo("\n{:45} {:20} {:20} {:20} {}".format("Account_UUID", "API Permitted", "Password Permitted",
                                                     "SAML Permitted", "User_UUID"))
    click.echo("-" * 150)

    click.echo("{:45} {:20} {:20} {:20} {}".format(str(info['account_uuid']), str(info['api_permitted']),
                                                   str(info['password_permitted']), str(info['saml_permitted']),
                                                   str(info['user_uuid'])))

    click.echo()


@info.command(help="Display Scan Policy Templates")
@click.option("-policy", is_flag=True, help="Display all Policy Templates")
@click.option("-scan", is_flag=True, help="Display all Scan Templates")
def templates(policy, scan):
    template_type = ""

    if policy:
        template_type = "policy"
    if scan:
        template_type = "scan"

    if template_type:
        try:
            click.echo("\n{:40s} {:61s} {}".format("Policy Name", "Description", "Template ID"))
            click.echo("-" * 150)

            for policy in tio.editor.template_list(str(template_type)):
                click.echo("{:40s} {:61s} {}".format(str(policy['name']), str(policy['title']),
                                                     policy['uuid']))
            click.echo()
        except AttributeError:
            click.echo("\nCheck your permissions or your API keys\n")
    else:
        click.echo("\nYou must use '-scan' or '-policy'")


@info.command(help="Display completed Audit files and Audit information")
@click.option('--name', default=None, help="Display all of the Assets with completed Audits "
                                           "for the Given Audit name")
@click.option('--uuid', default=None, help="Display all compliance findings for a given Asset UUID")
def audits(name, uuid):

    if name and uuid:
        data = db_query("SELECT asset_uuid, check_name, status FROM compliance where audit_file='{}' "
                        "and asset_uuid='{}';".format(name, uuid))

        click.echo("{:45} {:85} {}".format("\nAsset UUID", " Check Name", " Status"))
        click.echo("-" * 150)
        click.echo()
        for finding in data:
            click.echo("{:45} {:85} {}".format(textwrap.shorten(str(finding[0]), width=45),
                                               textwrap.shorten(str(finding[1]), width=85),
                                               finding[2]))
        click.echo()

    elif name:
        data = db_query("SELECT asset_uuid, check_name, status FROM compliance where audit_file='{}';".format(name))

        click.echo("{:45} {:85} {}".format("\nAsset UUID", " Check Name", " Status"))
        click.echo("-" * 150)
        click.echo()
        for finding in data:
            click.echo("{:45} {:85} {}".format(textwrap.shorten(str(finding[0]), width=45),
                                               textwrap.shorten(str(finding[1]), width=85),
                                               finding[2]))
        click.echo()

    elif uuid:
        data = db_query("SELECT asset_uuid, check_name, status FROM compliance where asset_uuid='{}';".format(uuid))

        click.echo("{:45} {:85} {}".format("\nAsset UUID", " Check Name", " Status"))
        click.echo("-" * 150)
        click.echo()
        for finding in data:
            click.echo("{:45} {:85} {}".format(textwrap.shorten(str(finding[0]), width=45),
                                               textwrap.shorten(str(finding[1]), width=85),
                                               finding[2]))
        click.echo()

    else:
        compliance_data = db_query("SELECT audit_file from compliance;")
        compliance_list = []

        for audit in compliance_data:
            if audit not in compliance_list:
                compliance_list.append(audit)

        click.echo("\nCompleted Audits")
        click.echo("-" * 80)
        click.echo()

        for name in compliance_list:
            click.echo(name[0])

        click.echo()


@info.command(help="Display Permissions")
def permissions():
    permission_data = request_data("GET", "/api/v3/access-control/permissions")
    try:
        click.echo("\n{:80s} {}".format("Name - Tag Category:Value - [perms]", "Subject(s)"))
        click.echo("-" * 150)

        for perm in permission_data['permissions']:
            subject_names = []
            for names in perm['subjects']:
                try:
                    subject_names.append(names['name'])
                except KeyError:
                    # All admins perm has no name
                    pass
            click.echo("{:80s} {}".format(textwrap.shorten(perm['name'], width=80),
                                          textwrap.shorten("{}".format(subject_names), width=70)))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@info.command(help="Display custom attributes")
def attributes():
    custom_attributes = request_data("GET", "/api/v3/assets/attributes")

    click.echo("\n{:60s} {:50} {}".format("Attribute Name", "Description", "UUID"))
    click.echo("-" * 150)
    for attr in custom_attributes['attributes']:
        attr_name = attr['name']
        attr_description = attr['description']
        attr_uuid = attr['id']
        click.echo("{:60s} {:50} {}".format(attr_name, attr_description, attr_uuid))
    click.echo()


@info.command(help="Display current SLA")
def sla():
    print_sla()


def find_by_plugin(pid):
    rows = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns "
                    "LEFT JOIN assets ON asset_uuid = uuid where plugin_id=%s" % pid)

    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    for row in rows:
        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(pid), row[0],
                                                          textwrap.shorten(row[2], 46), row[1], row[3]))

    click.echo()


@explore.group(help="Discover assets with Open ports, Running containers and more")
def data():
    pass


@data.command(help="Find Assets where a plugin fired using the plugin ID")
@click.argument('plugin_id')
@click.option('--o', '--output', default='', help='Find Assets based on the text in the output')
def plugin(plugin_id, o):
    if not str.isdigit(plugin_id):
        click.echo("You didn't enter a number")
        exit()
    else:
        if o != "":
            click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
            click.echo("-" * 150)

            plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON "
                                   "asset_uuid = uuid where plugin_id='" + plugin_id + "' and output LIKE '%" + o + "%';")

            for row in plugin_data:
                try:
                    fqdn = row[2]
                except:
                    fqdn = " "
                click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(plugin_id), row[0], textwrap.shorten(fqdn, 46), row[1], row[3]))

        else:
            find_by_plugin(plugin_id)


@data.command(help="Find Assets that have a given CVE iD")
@click.argument('cve_id')
def cve(cve_id):

    if len(cve_id) < 10:
        click.echo("\nThis is likely not a CVE...Try again...\n")

    elif "CVE" not in cve_id:
        click.echo("\nYou must have 'CVE' in your CVE string. EX: CVE-1111-2222\n")

    else:
        click.echo("\n{:8s} {:>8} {:16s} {:40s} {:38s} {}".format("Plugin", "EPSS", "IP Address", "FQDN", "UUID", "Network UUID"))
        click.echo("-" * 150)

        plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, plugin_id, network from vulns LEFT JOIN "
                               "assets ON asset_uuid = uuid where cves LIKE '%" + cve_id + "%';")

        for row in plugin_data:
            try:
                fqdn = row[2]
            except:
                fqdn = " "

            try:
                epss_data_raw = db_query("select epss_value from epss where cve='{}'".format(cve_id))
                epss_data = str(epss_data_raw[0][0])
            except:
                epss_data = 'No EPSS'

            click.echo("{:8s} {:>8} {:16s} {:40s} {:38s} {} ".format(row[3], epss_data, row[0],
                                                                     textwrap.shorten(fqdn, 40), row[1], row[4]))

        click.echo()


@data.command(help="Find Assets that have an exploitable vulnerability")
def exploit():

    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, plugin_id, network from vulns LEFT JOIN"
                           " assets ON asset_uuid = uuid where exploit = 'True';")

    for row in plugin_data:
        try:
            fqdn = row[2]
        except:
            fqdn = " "
        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[3], row[0],
                                                          textwrap.shorten(fqdn, 46), row[1], row[4]))

    click.echo()


@data.command(help="Find Assets where Text was found in the output of any plugin")
@click.argument('out_put')
def output(out_put):

    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network, plugin_id from vulns LEFT JOIN"
                           " assets ON asset_uuid = uuid where output LIKE '%" + str(out_put) + "%';")

    for row in plugin_data:
        try:
            fqdn = row[2]
        except:
            fqdn = " "
        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[4], row[0],
                                                          textwrap.shorten(fqdn, 46), row[1], row[3]))

    click.echo()


@data.command(help="Find Docker Hosts using plugin 93561")
def docker():
    click.echo("Searching for RUNNING docker containers...")
    find_by_plugin(str(93561))


@data.command(help="Find Potential Web Apps using plugin 1442 and 22964")
def webapp():

    click.echo("\nPotential Web Applications Report\n")

    rows = db_query("SELECT output, asset_uuid, asset_ip, network FROM vulns LEFT JOIN"
                    " assets ON asset_uuid = uuid where plugin_id ='12053';")

    for row in rows:
        host = row[0].split()
        final_host = host[3][:-1]
        uuid = row[1]

        click.echo("*" * 50)
        click.echo("Asset IP: {}".format(row[2]))
        click.echo("Asset UUID: {}".format(row[1]))
        click.echo("Network UUID: {}".format(row[3]))
        click.echo("*" * 50)

        new_row = db_query("SELECT output, port FROM vulns where plugin_id ='22964' and asset_uuid='{}';".format(uuid))
        click.echo("\nWeb Apps Found")
        click.echo("-" * 14)

        for service in new_row:
            if "web" in service[0]:
                if "through" in service[0]:
                    click.echo("https://{}:{}".format(final_host, service[1]))
                else:
                    click.echo("http://{}:{}".format(final_host, service[1]))

        doc_row = db_query("SELECT output, port FROM vulns where plugin_id ='93561' and asset_uuid='{}';".format(uuid))

        if doc_row:
            click.echo("\nThese web apps might be running on one or more of these containers:\n")

        for doc in doc_row:
            plug = doc[0].splitlines()
            for x in plug:
                if "Image" in x:
                    click.echo(x)
                if "Port" in x:
                    click.echo(x)
                    click.echo()
        click.echo("-" * 100)


@data.command(help="Find Assets with Credential Issues using plugin 104410")
def creds():
    click.echo("\nBelow are the Assets that have had Credential issues\n")
    find_by_plugin(104410)


@data.command(help="Find Assets that took longer than a given set of minutes to complete")
@click.argument('minute')
def scantime(minute):

    click.echo("\n*** Below are the assets that took longer than {} minutes to scan ***".format(str(minute)))

    data = db_query("SELECT asset_ip, asset_uuid, scan_started, scan_completed, "
                    "scan_uuid, output from vulns where plugin_id='19506';")

    try:
        click.echo("\n{:16s} {:40s} {:25s} {:25s} {}".format("Asset IP", "Asset UUID", "Started", "Finished", "Scan UUID"))
        click.echo("-" * 150)
        for vulns in data:
            plugin_dict = {}
            plugin_output = vulns[5]

            # split the output by return
            parsed_output = plugin_output.split("\n")

            for info_line in parsed_output:
                try:
                    new_split = info_line.split(" : ")
                    plugin_dict[new_split[0]] = new_split[1]

                except:
                    pass
            try:
                intial_seconds = plugin_dict['Scan duration']
            except KeyError:
                intial_seconds = 'unknown'

            # For an unknown reason, the scanner will print unknown for some
            # assets leaving no way to calculate the time.
            if intial_seconds != 'unknown':

                # Numerical value in seconds parsed from the plugin
                try:
                    seconds = int(intial_seconds[:-3])
                    minutes = seconds / 60
                except ValueError:
                    minutes = 0

                # grab assets that match the criteria
                if minutes > int(minute):
                    try:
                        click.echo("{:16s} {:40s} {:25s} {:25s} {}".format(str(vulns[0]), str(vulns[1]),
                                                                           str(vulns[2]), str(vulns[3]),
                                                                           str(vulns[4])))
                    except ValueError:
                        pass
        click.echo()
    except Exception as E:
        print(E)


@data.command(help="Find Assets that have not been scanned in any Cloud")
def ghost():
    click.echo("\n{:11s} {:15s} {:50} {}".format("Source", "IP", "FQDN", "First seen"))
    click.echo("-" * 150)

    for assets in tio.workbenches.assets(("sources", "set-hasonly", "AWS")):
        for source in assets['sources']:
            if source['name'] == 'AWS':
                try:
                    aws_ip = assets['ipv4'][0]
                except IndexError:
                    aws_ip = "No IP Found"
                try:
                    aws_fqdn = assets['fqdn'][0]
                except IndexError:
                    aws_fqdn = "No FQDN Found"

                click.echo("{:11s} {:15s} {:50} {}".format(str(source['name']), str(aws_ip),
                                                           str(aws_fqdn), source['first_seen']))
    click.echo()

    for gcp_assets in tio.workbenches.assets(("sources", "set-hasonly", "GCP")):
        for gcp_source in gcp_assets['sources']:
            if gcp_source['name'] == 'GCP':
                try:
                    gcp_ip = gcp_assets['ipv4'][0]
                except IndexError:
                    gcp_ip = "No IP Found"
                try:
                    gcp_fqdn = gcp_assets['fqdn'][0]
                except IndexError:
                    gcp_fqdn = "NO FQDN FOUND"

                click.echo("{:11s} {:15s} {:50} {}".format(gcp_source['name'], gcp_ip, gcp_fqdn,
                                                           gcp_source['first_seen']))
    click.echo()

    for az_assets in tio.workbenches.assets(("sources", "set-hasonly", "AZURE")):
        for az_source in az_assets['sources']:
            if az_source['name'] == 'AZURE':
                try:
                    az_ip = az_assets['ipv4'][0]
                except IndexError:
                    az_ip = "No IP Found"

                try:
                    az_fqdn = az_assets['fqdn'][0]
                except IndexError:
                    az_fqdn = "NO FQDN Found"

                click.echo("{:11s} {:15s} {:50} {}".format(az_source['name'], az_ip, az_fqdn,
                                                           az_source['first_seen']))
    click.echo()


@data.command(help="Find Assets with a given port open")
@click.argument('open_port')
def port(open_port):
    data = db_query("SELECT plugin_id, asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN "
                    "assets ON asset_uuid = uuid where port=" + open_port + " and "
                    "(plugin_id='11219' or plugin_id='14272' or "
                    "plugin_id='14274' or plugin_id='34220' or plugin_id='10335');")

    try:
        click.echo("\nThe Following assets had Open ports found by various plugins")
        click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address",
                                                            "FQDN", "UUID", "Network UUID"))
        click.echo("-" * 150)

        for vulns in data:
            try:
                fqdn = vulns[3]
            except:
                fqdn = " "

            click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(vulns[0]), vulns[1],
                                                              textwrap.shorten(fqdn, 46),
                                                              vulns[2], vulns[4]))

        click.echo()
    except ValueError:
        pass


@data.command(help="Find Assets using a custom SQL query.")
@click.argument('statement')
def query(statement):
    data = db_query(statement)
    pprint.pprint(data)


@data.command(help="Find Assets where a plugin fired with TEXT found in a plugin name")
@click.argument('plugin_name')
def name(plugin_name):

    plugin_data = db_query("SELECT asset_ip, asset_uuid, plugin_name, "
                           "plugin_id from vulns where plugin_name LIKE '%" + plugin_name + "%';")

    click.echo("\nThe Following assets had '{}' in the Plugin Name".format(plugin_name))
    click.echo("\n{:8s} {:20} {:45} {:70} ".format("Plugin", "IP address", "UUID", "Plugin Name"))
    click.echo("-" * 150)

    for vulns in plugin_data:
        click.echo("{:8s} {:20} {:45} {:70}".format(vulns[3], vulns[0], str(vulns[1]),
                                                    textwrap.shorten(str(vulns[2]), 65)))

    click.echo()


@data.command(help="Find Assets that have a Cross Reference Type and/or ID")
@click.argument('xref')
@click.option("--xid", "--xref-id", default='', help="Specify a Cross Reference ID")
def xrefs(xref, xid):
    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    if xid:
        xref_data = db_query("select plugin_id, asset_ip, fqdn, asset_uuid, network, xrefs from vulns LEFT JOIN"
                             " assets ON asset_uuid = uuid where xrefs "
                             "LIKE '%{}%' AND xrefs LIKE '%{}%'".format(xref, xid))

    else:
        xref_data = db_query("select plugin_id, asset_ip, fqdn, asset_uuid, network, xrefs from vulns LEFT JOIN"
                             " assets ON asset_uuid = uuid where xrefs LIKE '%{}%'".format(xref))

    for row in xref_data:
        try:
            fqdn = row[2]
        except:
            fqdn = " "

        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[0], row[1],
                                                          textwrap.shorten(fqdn, 46), row[3], row[4]))

    click.echo()


def plugin_by_ip(ipaddr, plugin):
    try:
        if len(ipaddr) < 17:
            rows = db_query("SELECT output, cves, score, state, xrefs from vulns where asset_ip=\"%s\" and plugin_id=%s" % (ipaddr, plugin))
        else:
            rows = db_query("SELECT output, cves, score, state, xrefs from vulns where asset_uuid=\"%s\" and plugin_id=%s" % (ipaddr, plugin))

        for plug in rows:
            click.echo("\nCurrent Plugin State: {} ".format(plug[3]))
            if plug[2] != ' ':
                click.echo("\nVPR Score: {}".format(plug[2]))

            if plug[4] != ' ':
                click.echo("\nCross References\n")
                click.echo("-" * 80)
                for xref in eval(plug[4]):
                    click.echo("Type: {}".format(xref['type']))
                    click.echo("ID: {}".format(xref['id']))
                    click.echo()

            click.echo("\nPlugin Output")
            click.echo("-" * 60)
            click.echo(plug[0])

            if plug[1] != ' ':
                click.echo("CVEs attached to this plugin")
                click.echo("-" * 80)
                click.echo("{}\n".format(plug[1]))

                total = 0
                epss_list = []
                try:
                    for cve in eval(plug[1]):
                        database = r"navi.db"
                        conn = new_db_connection(database)
                        with conn:
                            cur = conn.cursor()

                            cur.execute("select epss_value from epss where cve='{}'".format(cve))
                            epss_value = cur.fetchall()
                            epss_list.append(eval(epss_value[0][0]))
                            total += total + eval(epss_value[0][0])

                    average = total/len(epss_list)
                    top = max(epss_list)
                    click.echo("{:>15} {:>15} {:>15}".format("EPSS Average", "EPSS Max", "EPSS Total"))
                    click.echo("-" * 80)
                    click.echo("{:>15} {:>15} {:>15}".format(average, top, total))
                except:
                    pass
        click.echo()
    except IndexError:
        click.echo("No information found for this plugin")


def vulns_by_uuid(uuid):
    try:
        data = db_query("select plugin_id, plugin_name, plugin_family, port, protocol, "
                        "severity, state from vulns where asset_uuid='{}' and severity !='info';".format(uuid))

        click.echo("\n{:10s} {:70s} {:35s} {:10s} {:6s} {:6s} {}".format("Plugin", "Plugin Name",
                                                                         "Plugin Family", "state",
                                                                         "Port", "Proto", "Severity"))
        click.echo("-"*150)

        for vulns in data:
            plugin_id = vulns[0]
            plugin_name = vulns[1]
            plugin_family = vulns[2]
            port = vulns[3]
            protocol = vulns[4]
            severity = vulns[5]
            state = vulns[6]
            click.echo("{:10s} {:70s} {:35s} {:10s} {:6s} {:6s} {}".format(plugin_id,
                                                                           textwrap.shorten(plugin_name, 70),
                                                                           textwrap.shorten(plugin_family, 35),
                                                                           state, port, protocol, severity))
        click.echo("")
    except Error as e:
        click.echo(e)


def get_attributes(uuid):
    attr_data = request_data('GET', '/api/v3/assets/{}/attributes'.format(uuid))
    return attr_data


def info_by_uuid(uuid):
    try:
        data = db_query("select plugin_id, plugin_name, plugin_family, port, protocol, severity from vulns where asset_uuid='{}' and severity =='info';".format(uuid))

        click.echo("\n{:10s} {:90s} {:25s} {:6s} {:6s} {}".format("Plugin", "Plugin Name", "Plugin Family", "Port", "Proto", "Severity"))
        click.echo("-"*150)

        for vulns in data:
            plugin_id = vulns[0]
            plugin_name = vulns[1]
            plugin_family = vulns[2]
            port = vulns[3]
            protocol = vulns[4]
            severity = vulns[5]
            click.echo("{:10s} {:90s} {:25s} {:6s} {:6s} {}".format(plugin_id, plugin_name, plugin_family, port, protocol, severity))
        click.echo("")
    except Error as e:
        click.echo(e)


def cves_by_uuid(uuid):

    try:
        data = db_query("select plugin_id, cves from vulns where asset_uuid='{}' and cves !=' ';".format(uuid))

        click.echo("\n{:10s} {:90} {:>15} {:>15} {:>15}".format("Plugin", "CVEs", "Avg EPSS", "Total EPSS", "Top EPSS"))
        click.echo("-"*150)

        for vulns in data:
            plugin_id = vulns[0]
            cves = vulns[1]
            try:
                total = 0
                epss_list = []

                for cve in eval(cves):
                    database = r"navi.db"
                    conn = new_db_connection(database)
                    with conn:
                        cur = conn.cursor()

                        cur.execute("select epss_value from epss where cve='{}'".format(cve))
                        epss_value = cur.fetchall()
                        epss_list.append(eval(epss_value[0][0]))
                        total += total + eval(epss_value[0][0])

                average = total/len(epss_list)
                top = max(epss_list)
                click.echo("{:10s} {:90} {:15} {:15} {:15}".format(plugin_id, textwrap.shorten(cves, 90),
                                                                   average, total, top))
            except:
                average = "No EPSS"
                total = "No EPSS"
                top = "No EPSS"
                click.echo("{:10s} {:90} {:>15} {:>15} {:>15}".format(plugin_id, textwrap.shorten(cves, 90),
                                                                      average, total, top))

    except IndexError:
        click.echo("Something went wrong")


@explore.command(help="Get Asset details based on IP or UUID")
@click.argument('ipaddr')
@click.option('--plugin', default='', help='Find Details on a particular plugin ID')
@click.option('-n', '-netstat', is_flag=True, help='Netstat Established(58561) and Listening and Open Ports(14272)')
@click.option('-p', '-patch', is_flag=True, help='Patch Information - 66334')
@click.option('-t', '-tracert', is_flag=True, help='Trace Route - 10287')
@click.option('-o', '-processes', is_flag=True, help='Process Information - 70329')
@click.option('-c', '-connections', is_flag=True, help='Connection Information - 64582')
@click.option('-s', '-services', is_flag=True, help='Services Running - 22964')
@click.option('-r', '-firewall', is_flag=True, help='Local Firewall Rules - 56310')
@click.option('-patches', is_flag=True, help='Missing Patches - 38153')
@click.option('-d', is_flag=True, help="Scan Detail: 19506 plugin output")
@click.option('-software', is_flag=True, help="Find software installed on Unix(22869) of windows(20811) hosts")
@click.option('-outbound', is_flag=True, help="outbound connections found by nnm")
@click.option('-exploit', is_flag=True, help="Display Solution, Description for each Exploit")
@click.option('-critical', is_flag=True, help="Display Plugin Output for each Critical Vuln")
@click.option('-details', is_flag=True, help="Details on an Asset: IP, UUID, Vulns, etc")
@click.option('-vulns', is_flag=True, help="Display all vulnerabilities and their plugin IDs")
@click.option('-info', is_flag=True, help="Display all info plugins and their IDs")
@click.option('-cves', is_flag=True, help="Display all cves found on the asset")
@click.option('-compliance', '-audits', is_flag=True, help="Display all Compliance info for a given asset UUID")
@click.pass_context
def uuid(ctx, ipaddr, plugin, n, p, t, o, c, s, r, patches, d, software, outbound, exploit, critical, details, vulns,
       info, cves, compliance):

    if d:
        click.echo('\nScan Detail')
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(19506))

    if n:
        click.echo("\nNetstat info")
        click.echo("Established and Listening")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(58651))
        click.echo("\nNetstat Open Ports")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(14272))

    if p:
        click.echo("\nPatch Information")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(66334))

    if t:
        click.echo("\nTrace Route Info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(10287))

    if o:
        click.echo("\nProcess Info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(70329))
        plugin_by_ip(ipaddr, str(110483))

    if patches:
        click.echo("\nMissing Patches")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(38153))
        plugin_by_ip(ipaddr, str(66334))

        click.echo("\nLast Reboot")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(56468))

    if c:
        click.echo("\nConnection info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(64582))

    if s:
        try:
            if len(ipaddr) < 17:
                data = db_query("SELECT output, port from vulns where asset_ip=\"%s\" and plugin_id='22964'" % ipaddr)
            else:
                data = db_query("SELECT output, port from vulns where asset_uuid=\"%s\" and plugin_id='22964'" % ipaddr)

            for plugins in data:
                output = plugins[0]
                port = plugins[1]
                click.echo("\n{} {}".format(str(output), str(port)))
            click.echo()
        except IndexError:
            click.echo("No information for plugin 22964")

    if r:
        click.echo("Local Firewall Info")
        click.echo("-" * 15)
        plugin_by_ip(ipaddr, str(56310))
        plugin_by_ip(ipaddr, str(61797))

    if software:
        try:
            plugin_by_ip(ipaddr, str(22869))
            plugin_by_ip(ipaddr, str(20811))
        except IndexError:
            click.echo("No Software found")

    if outbound:
        try:
            if len(ipaddr) < 17:
                data = db_query("SELECT output, port, protocol from vulns where asset_ip=\"%s\" "
                                "and plugin_id='16'" % ipaddr)
            else:
                data = db_query("SELECT output, port, protocol from vulns where asset_uuid=\"%s\" "
                                "and plugin_id='16'" % ipaddr)

            click.echo("\n{:15s} {:5} {}".format("IP address", "Port", "Protocol"))
            click.echo("-" * 25)
            for plugins in data:
                output = plugins[0]
                port = plugins[1]
                proto = plugins[2]
                click.echo("\n{:15s} {:5} {}".format(str(output), str(port), str(proto)))
            click.echo()
        except Exception as E:
            click.echo("No information for plugin 16")
            click.echo(E)

    if exploit:
        try:
            if len(ipaddr) < 17:
                intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
                data = set(intial_data)
            else:
                data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))

            for assets in data:
                asset_id = assets[0]

                click.echo("\nExploitable Details for : {}\n".format(ipaddr))

                vuln_data = tio.workbenches.asset_vulns(asset_id, ("plugin.attributes.exploit_available", "eq", "true"), age=90)

                for plugins in vuln_data:
                    plugin = plugins['plugin_id']

                    plugin_data = tio.plugins.plugin_details(plugin)

                    click.echo("\n----Exploit Info----")
                    click.echo(plugin_data['name'])
                    click.echo()
                    for attribute in plugin_data['attributes']:

                        if attribute['attribute_name'] == 'cve':
                            cve = attribute['attribute_value']
                            click.echo("CVE ID : " + cve)

                        if attribute['attribute_name'] == 'description':
                            description = attribute['attribute_value']
                            click.echo("Description")
                            click.echo("------------\n")
                            click.echo(description)
                            click.echo()

                        if attribute['attribute_name'] == 'solution':
                            solution = attribute['attribute_value']
                            click.echo("\nSolution")
                            click.echo("------------\n")
                            click.echo(solution)
                            click.echo()
        except Exception as E:
            click.echo(E)

    if critical:
        try:
            if len(ipaddr) < 17:

                intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
                data = set(intial_data)
            else:
                data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))

            for assets in data:
                asset_id = assets[0]
                click.echo("\nCritical Vulns for Ip Address : {}\n".format(ipaddr))

                asset_vulns = tio.workbenches.asset_vulns(asset_id, age=90)

                for severities in asset_vulns:
                    vuln_name = severities["plugin_name"]
                    plugin_id = severities["plugin_id"]
                    severity = severities["severity"]
                    state = severities["vulnerability_state"]

                    # only pull the critical vulns; critical = severity 4
                    if severity >= 4:
                        click.echo("Plugin Name : {}".format(vuln_name))
                        click.echo("ID : {}".format(str(plugin_id)))
                        click.echo("Severity : Critical")
                        click.echo("State : {}".format(state))
                        click.echo("----------------\n")
                        plugin_by_ip(str(ipaddr), str(plugin_id))
                        click.echo()
        except Exception as E:
            click.echo(E)

    if details:
        if len(ipaddr) < 17:
            intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
            data = set(intial_data)
        else:
            data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))

        try:
            for assets in data:
                asset_data = tio.workbenches.asset_info(str(assets[0]))

                try:
                    asset_id = asset_data['id']

                    click.echo("\nTenable ID")
                    click.echo("--------------")
                    click.echo(asset_id)

                    click.echo("\nNetwork Name")
                    click.echo("--------------")
                    click.echo(asset_data['network_name'])

                    click.echo("\nIdentities")
                    click.echo("--------------")
                    try:
                        for netbioss in asset_data['netbios_name']:
                            click.echo("Netbios - {}".format(netbioss))
                    except KeyError:
                        pass
                    try:
                        for fqdns in asset_data['fqdns']:
                            click.echo("FQDN - {}".format(fqdns))
                    except KeyError:
                        pass

                    try:
                        for hosts in asset_data['hostname']:
                            click.echo("Host Name - {}".format(hosts))
                    except KeyError:
                        pass

                    try:
                        for agentname in asset_data['agent_name']:
                            click.echo("Agent Name - {}".format(agentname))
                    except KeyError:
                        pass

                    try:
                        for awsid in asset_data['aws_ec2_instance_id']:
                            click.echo("AWS EC2 Instance ID - {}".format(awsid))
                    except KeyError:
                        pass

                    try:
                        for awsamiid in asset_data['aws_ec2_ami_id']:
                            click.echo("AWS EC2 AMI ID - {}".format(awsamiid))
                    except KeyError:
                        pass

                    try:
                        for awsname in asset_data['aws_ec2_name']:
                            click.echo("AWS EC2 Name - {}".format(awsname))
                    except KeyError:
                        pass

                    click.echo("\nOperating Systems")
                    click.echo("--------------")
                    try:
                        for oss in asset_data['operating_system']:
                            click.echo(oss)
                    except KeyError:
                        pass

                    try:
                        click.echo("\nIP Addresses:")
                        click.echo("--------------")
                        for ips in asset_data['ipv4']:
                            click.echo(ips)
                    except KeyError:
                        pass

                    try:
                        click.echo("\nMac Addresses:")
                        click.echo("--------------")
                        for macs in asset_data['mac_address']:
                            click.echo(macs)
                    except KeyError:
                        pass

                    try:
                        click.echo("\nCloud Information:")
                        click.echo("--------------")
                        for zone in asset_data['aws_availability_zone']:
                            click.echo("AWS Availability Zone - {}".format(zone))
                    except KeyError:
                        pass

                    try:
                        for groupname in asset_data['aws_ec2_instance_group_name']:
                            click.echo("AWS Instance group Name - {}".format(groupname))
                    except KeyError:
                        pass

                    try:
                        for zone in asset_data['aws_availability_zone']:
                            click.echo("AWS Availability Zone - {}".format(zone))
                    except KeyError:
                        pass
                    try:
                        for statename in asset_data['aws_ec2_instance_state_name']:
                            click.echo("AWS Instance State - {}".format(statename))
                    except KeyError:
                        pass
                    try:
                        for instatncetype in asset_data['aws_ec2_instance_type']:
                            click.echo("AWS Instance Type - {}".format(instatncetype))
                    except KeyError:
                        pass
                    try:
                        for region in asset_data['aws_region']:
                            click.echo("AWS Region - {}".format(region))
                    except KeyError:
                        pass

                    try:
                        for subnet in asset_data['aws_subnet_id']:
                            click.echo("AWS Subnet ID - {}".format(subnet))
                    except KeyError:
                        pass
                    try:
                        for vpc in asset_data['aws_vpc_id']:
                            click.echo("AWS VPC ID - {}".format(vpc))
                    except KeyError:
                        pass
                    try:
                        for azureid in asset_data['azure_resource_id']:
                            click.echo("Azure Resource ID - {}".format(azureid))
                    except KeyError:
                        pass
                    try:
                        for vmid in asset_data['azure_vm_id']:
                            click.echo("Azure VM ID - {}".format(vmid))
                    except KeyError:
                        pass

                    try:
                        for gcpid in asset_data['gcp_instance_id']:
                            click.echo("GCP Instance ID - {}".format(gcpid))
                    except KeyError:
                        pass
                    try:
                        for projectid in asset_data['gcp_project_id']:
                            click.echo("GCP Project ID- {}".format(projectid))
                    except KeyError:
                        pass
                    try:
                        for gcpzone in asset_data['gcp_zone']:
                            click.echo("GCP Zone - {}".format(gcpzone))
                    except KeyError:
                        pass
                    try:
                        click.echo("\nSources:")
                        click.echo("-" * 15)
                        for source in asset_data['sources']:
                            click.echo(source['name'])
                    except KeyError:
                        pass
                    try:
                        click.echo("\nTags:")
                        click.echo("-" * 15)
                        for tags in asset_data['tags']:
                            click.echo("{} : {}".format(tags["tag_key"], tags['tag_value']))
                    except KeyError:
                        pass
                    try:
                        click.echo("\nCustom Attributes:")
                        click.echo("-" * 15)
                        for attr in get_attributes(ipaddr)['attributes']:
                            click.echo("{} : {}".format(attr['name'], attr['value']))

                    except KeyError:
                        pass
                    click.echo("\nVulnerability Counts")
                    click.echo("-" * 15)

                    asset_info = tio.workbenches.asset_info(asset_id)

                    for vuln in asset_info['counts']['vulnerabilities']['severities']:
                        click.echo("{} : {}".format(vuln["name"], vuln["count"]))

                    try:
                        click.echo("\nAsset Exposure Score : {}".format(asset_info['exposure_score']))
                        click.echo("\nAsset Criticality Score : {}".format(asset_info['acr_score']))
                    except KeyError:
                        pass

                    click.echo("\nLast Authenticated Scan Date - {}".format(asset_data['last_authenticated_scan_date']))
                    click.echo("\nLast Licensed Scan Date - {}".format(asset_data['last_licensed_scan_date']))
                    click.echo("-" * 50)
                    click.echo("-" * 50)
                except KeyError:
                    pass
        except:
            click.echo("\nWorkbench data couldn't be received, this could mean the asset UUID or IP doesn't exist "
                       "or was recently deleted.\n")

    if vulns:
        if len(ipaddr) < 17:
            intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
            data = set(intial_data)
            for assets in data:
                click.echo("\nAsset UUID: {}".format(ipaddr))
                click.echo("Asset IP: {}".format(ipaddr))
                click.echo("-" * 26)
                vulns_by_uuid(assets[0])
        else:
            data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))
            click.echo("\nAsset UUID: {}".format(ipaddr))
            click.echo("Asset IP: {}".format(data[0]))
            click.echo("-" * 26)
            vulns_by_uuid(ipaddr)

    if cves:
        if len(ipaddr) < 17:
            intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
            data = set(intial_data)

            for assets in data:
                click.echo("\nAsset UUID: {}".format(assets[0]))
                click.echo("Asset IP: {}".format(ipaddr))
                click.echo("-" * 26)
                cves_by_uuid(assets[0])
        else:
            click.echo("\nAsset UUID: {}".format(ipaddr))
            click.echo("-" * 26)
            cves_by_uuid(ipaddr)

    if info:
        if len(ipaddr) < 17:
            intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
            data = set(intial_data)

            for assets in data:
                click.echo("\nAsset UUID: {}".format(assets[0]))
                click.echo("Asset IP: {}".format(ipaddr))
                click.echo("-" * 26)
                info_by_uuid(assets[0])
        else:
            data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))
            click.echo("\nAsset UUID: {}".format(ipaddr))
            click.echo("Asset IP: {}".format(data[0]))
            click.echo("-" * 26)
            info_by_uuid(ipaddr)

    if plugin != '':
        plugin_by_ip(ipaddr, plugin)

    if compliance:
        if len(ipaddr) > 16:
            compliance_data = db_query("SELECT check_name, status, audit_file from compliance "
                                       "where asset_uuid='{}';".format(ipaddr))
            click.echo("{:84} {:8} {}".format("Check Name", "Status", "Audit File"))
            click.echo("-" * 150)
            for finding in compliance_data:
                check_name = finding[0]
                status = finding[1]
                audit_file = finding[2]
                click.echo("{:85} {:8} {}".format(textwrap.shorten(check_name, width=80), status,
                                                  textwrap.shorten(audit_file, width=60)))
        else:
            click.echo("\nCompliance info requires a UUID\n\nFor simplicity I pulled the UUID(s) with this IP\nPlease "
                       "re-run your command using one of the below UUIDs")
            uuid_data = db_query("SELECT asset_uuid, asset_hostname from vulns where asset_uuid='{}';".format(ipaddr))

            click.echo("{:45}{}".format("UUID", "FQDN"))
            click.echo("-" * 150)
            for address in uuid_data:
                click.echo("{:45}{}".format(address[0], address[1]))
            click.echo()


@explore.command(help="Explore the API using simple GET requests ex: 'navi api /scans ")
@click.argument('url')
@click.option('-raw', is_flag=True, help="Return raw Json")
@click.option('--limit', default=50, help="Change API Request Limit")
@click.option('--offset', default=0, help="Change API Request Offset")
@click.option('-post', is_flag=True, help="Use POST instead of GET")
@click.option('--payload', help="Used for Automation; Receives a well crafted payload in json")
def api(url, raw, limit, offset, post, payload):
    params = {"limit": limit, "offset": offset}
    try:
        if post:
            if payload:
                data = request_data('POST', url, params=params, payload=payload)
            else:
                data = request_data('POST', url, params=params)
        else:
            data = request_data('GET', url, params=params)

        if not raw:
            pprint.pprint(data)
        else:
            click.echo(data)

    except Exception as E:
        error_msg(E)


@info.command(help="Display stats on Software")
@click.option('-missing', is_flag=True, help="Display assets missing software enumeration")
@click.option('-stats', is_flag=True, help="Display General Stats")
@click.option('--greaterthan', default=None,
              help="Display Software installed Greater than or equal to the number entered")
@click.option('--lessthan', default=None,
              help="Display Software installed less than or equal to the number entered")
def software(missing, stats, greaterthan, lessthan):

    if missing:
        click.echo("\nThese Assets do not have plugin 22869 nor 20811\n")
        assets_without_data = db_query("select hostname, uuid, ip_address, acr, aes from assets where "
                                       "ip_address !=' ' and uuid not in "
                                       "(select distinct asset_uuid from vulns "
                                       "where plugin_id ='22869' or plugin_id ='20811')")

        click.echo("\n{:16} {:80} {:6} {:6} {}".format("IP Address", "FQDN", "AES", "ACR", "UUID"))
        click.echo("-" * 150)

        for asset in assets_without_data:
            ipv4 = str(asset[2])
            fqdn = str(asset[0])
            uuid = str(asset[1])
            exposure_score = str(asset[4])
            acr = str(asset[3])

            click.echo("{:16} {:80} {:6} {:6} {}".format(ipv4, textwrap.shorten(fqdn, width=80), exposure_score, acr, uuid))
        click.echo()

    if stats:
        display_stats()

    if greaterthan:
        try:
            click.echo()
            click.echo("*"*50)
            click.echo("Below is the Software found {} times or more".format(greaterthan))
            click.echo("*" * 50)
            all_data = db_query("select * from software;")
            click.echo("{:125} {}".format("\nSoftware Package Name", "Install Count"))
            click.echo('-' * 150)
            for wares in all_data:
                length = len(eval(wares[0]))
                if int(length) >= int(greaterthan):
                    click.echo("{:125} {}".format(wares[1], len(eval(wares[0]))))
        except:
            click.echo("\nRun navi sofware Generate\n Or check your input\n")
        click.echo()

    if lessthan:
        try:
            click.echo("*" * 50)
            click.echo("Below is the Software found {} times or less".format(greaterthan))
            click.echo("*" * 50)
            all_data = db_query("select * from software;")
            click.echo("{:125} {}".format("\nSoftware Package Name", "Install Count"))
            click.echo('-' * 150)
            for wares in all_data:
                length = len(eval(wares[0]))
                if int(length) <= int(lessthan):
                    click.echo("{:125} {}".format(wares[1], len(eval(wares[0]))))
        except:
            click.echo("\nRun navi sofware Generate\n Or check your input\n")
        click.echo()

