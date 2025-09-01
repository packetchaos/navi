import time
import arrow
from .api_wrapper import tenb_connection, navi_version, request_data
from .database import new_db_connection, db_query
from .fixed_export import print_sla
import click
import pprint
import textwrap
from .config import grab_data_info, display_routes, display_paths
from .query_export import query_export
from restfly import errors as resterrors

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
    except IndexError:
        click.echo("\nYou need to run 'navi config software' to populate the software table.\n")


def get_licensed():
    licensed_data = request_data('GET', '/workbenches/asset-stats?date_range=90&'
                                 'filter.0.filter=is_licensed&filter.0.quality=eq&filter.0.value=true')
    number_of_assets = licensed_data['scanned']
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
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


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
        click.echo("\n{:34s} {:40s} {:40s} {:10s} {}".format("User Name",
                                                             "Login Email", "UUID", "ID", "Enabled"))
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
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


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
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display running Scans")
def running():
    try:
        click.echo("\n{:60s} {:10s} {:30s}".format("Scan Name", "Scan ID", "Status"))
        click.echo("-" * 150)

        for scan in tio.scans.list():
            if scan['status'] == "running":
                click.echo("{:60s} {:10s} {:30s}".format(str(scan['name']),
                                                         str(scan['id']), str(scan['status'])))

        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display Scans")
@click.option("-a", is_flag=True, help="Display all scans")
def scans(a):
    try:
        click.echo("\n{:80s} {:5s} {:10s} {:40}".format("Scan Name", "ID", "Status", "UUID"))
        click.echo("-" * 150)

        if a:
            for scan in tio.scans.list():
                try:
                    click.echo("{:80s} {:5s} {:10s} {:40}".format(textwrap.shorten(str(scan['name']), width=80),
                                                                  str(scan['id']), str(scan['status']),
                                                                  str(scan['uuid'])))
                except KeyError:
                    click.echo("{:80s} {:5s} {:10s} {:40}".format(textwrap.shorten(str(scan['name']), width=80),
                                                                  str(scan['id']), str(scan['status']),
                                                                  "No UUID"))
        else:
            for scan in tio.scans.list():
                if str(compare_dates(scan['last_modification_date'])) == 'yes':
                    try:
                        click.echo("{:80s} {:5s} {:10s} {:40}".format(textwrap.shorten(
                            str(scan['name']), width=80), str(scan['id']), str(scan['status']), str(scan['uuid'])))
                    except KeyError:
                        click.echo("{:80s} {:5s} {:10s} {:40}".format(textwrap.shorten(
                            str(scan['name']), width=80), str(scan['id']), str(scan['status']), "No UUID"))
                else:
                    pass
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display All Assets found in the last 30 days")
@click.option("--tag", default='', help="Display Assets membership of a given Tag.  "
                                        "Use Tag Value UUID found in the command 'navi display tags'")
@click.option("--net", default='', required=True, help="Select Network ID")
def assets(tag, net):
    if tag:
        tag_data = db_query("select ip_address, fqdn, aes, acr from assets "
                            "LEFT JOIN tags ON uuid == asset_uuid where tag_uuid=='{}' order by aes DESC;".format(tag))

        click.echo("\nBelow are the assets that are apart of the Tag")
        click.echo("\n{:16} {:80} {:6} {}".format("IP Address", "FQDN", "AES", "ACR"))
        click.echo("-" * 150)
        try:
            for asset in tag_data:
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
            net_data = cur.fetchall()

            click.echo("\n{:25s} {:65s} {}".format("IP Address",
                                                   "Full Qualified Domain Name", "Licensed Scan Date"))
            click.echo("-" * 150)
            click.echo()

            for asset in net_data:
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
            asset_data = db_query("select ip_address, fqdn, uuid, aes from assets order by aes DESC;")
            for asset in asset_data:

                click.echo("{:16} {:80} {:40} {:6} ".format(asset[0],
                                                            textwrap.shorten(asset[1], width=80), asset[2],
                                                            str(asset[3])))

            click.echo("\nTotal: {}\n\n".format(len(asset_data)))
        except AttributeError:
            click.echo("\nCheck your permissions or your API keys\n")
        except TypeError:
            click.echo("\nCheck your permissions or your API keys\n")
        except resterrors.ForbiddenError:
            click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


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
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display TVM Status and Account info")
def status():
    try:
        status_data = tio.server.properties()
        session_data = tio.session.details()
        click.echo("\nTenable IO Information")
        click.echo("-" * 25)
        click.echo("{} {}".format("Container ID : ", session_data["container_id"]))
        click.echo("{} {}".format("Container UUID :", session_data["container_uuid"]))
        click.echo("{} {}".format("Container Name : ", session_data["container_name"]))
        click.echo("{} {}".format("Site ID :", status_data["analytics"]["site_id"]))
        click.echo("{} {}".format("Region : ", status_data["region"]))

        click.echo("\nLicense information")
        click.echo("-" * 25)
        click.echo("{} {}".format("Licensed Assets : ", get_licensed()))
        click.echo("{} {}".format("Agents Used : ", status_data['license']["agents"]))
        try:
            click.echo("{} {}".format("Expiration Date : ", status_data['license']["expiration_date"]))
        except KeyError:
            pass
        click.echo("{} {}".format("Scanners Used : ", status_data['license']["scanners"]))
        click.echo("{} {}".format("Users : ", status_data["license"]["users"]))

        click.echo("\nEnabled Apps")
        click.echo("-" * 15)
        click.echo()
        try:
            for key in status_data["license"]["apps"]:
                click.echo(key)
                click.echo("-" * 5)
                try:
                    click.echo("{} {}".format("Expiration: ",
                                              str(status_data["license"]["apps"][key]["expiration_date"])))
                except KeyError:
                    pass
                click.echo("{} {}".format("Mode: ", str(status_data["license"]["apps"][key]["mode"])))
                click.echo()
        except KeyError:
            pass

    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display Agent information")
@click.option("-show_uuid", is_flag=True, help="Display information on all agents including Agent UUID")
@click.option("--agent_id", default="", help="Get detailed information about a specific Agent")
def agents(show_uuid, agent_id):

    if agent_id:
        try:
            agent_details = tio.agents.details(agent_id)

            click.echo("\nAgent Details")
            click.echo("-----------------\n")
            click.echo("Agent Name: {}".format(agent_details['distro']))
            click.echo("Agent IP: {}".format(agent_details['distro']))
            click.echo("Agent UUID: {}".format(agent_details['uuid']))
            click.echo("Network UUID: {}".format(agent_details['network_uuid']))
            click.echo("Plugin Feed: {}".format(agent_details['plugin_feed_id']))

            click.echo("\nDistribution Information")
            click.echo("----------------------------\n")
            click.echo("Platform: {}".format(agent_details['platform']))
            click.echo("Distribution: {}".format(agent_details['distro']))
            click.echo("Core Version: {}".format(agent_details['core_version']))
            click.echo("Core Build: {}".format(agent_details['core_build']))

            click.echo("\nAgent Connection information")
            click.echo("----------------------------\n")
            click.echo("Last Connect Time: {}".format(agent_details['last_connect']))
            try:
                click.echo("Last Scan Time: {}".format(agent_details['last_scanned']))
            except KeyError:
                click.echo("Not Scanned Yet")
            click.echo("Restart Pending: {}".format(agent_details['restart_pending']))
            click.echo("Status: {}".format(agent_details['status']))

            click.echo("\nAgent Groups")
            click.echo("----------------------------\n")
            for agent_grps in agent_details['groups']:
                click.echo("Group Name({}): {}".format(str(agent_grps['id']), str(agent_grps['name'])))
        except TypeError:
            click.echo("\nYou need the Agent ID... Try again\n")
            exit()
        except resterrors.ForbiddenError:
            click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")

    else:
        try:
            if show_uuid:
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

                if show_uuid:
                    click.echo("{:30s} {:20s} {:20s} {:20s} {:6s} {}".format(textwrap.shorten(str(agent['name']),
                                                                                              width=30),
                                                                             str(agent['ip']), str(last_connect_time),
                                                                             str(last_scanned_time),
                                                                             str(agent['status']),
                                                                             textwrap.shorten(agent_uuid, width=60)))
                else:
                    click.echo("{:30s} {:20s} {:20s} {:20s} {:6s} {}".format(textwrap.shorten(str(agent['name']),
                                                                                              width=30),
                                                                             str(agent['ip']), str(last_connect_time),
                                                                             str(last_scanned_time),
                                                                             str(agent['status']),
                                                                             textwrap.shorten(groups[1:], width=60)))
            click.echo()
        except AttributeError:
            click.echo("\nCheck your permissions or your API keys\n")
        except resterrors.ForbiddenError:
            click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display Agent Groups and membership information ")
@click.option("--group_id", default=None,
              help="Display the agents that are members of the group using the group ID")
def agent_groups(group_id):

    if group_id:
        try:
            group_details = tio.agent_groups.details(group_id)
            click.echo("\n{:85s} {:15} {:40}".format("Agent Name", "Agent ID", "UUID", "Status"))
            click.echo("-" * 150)

            for agent_info in group_details['agents']:
                click.echo("{:85s} {:15} {:40s}".format(textwrap.shorten(str(agent_info['name']), width=85),
                                                        str(agent_info['id']),
                                                        str(agent_info['uuid']), str(agent_info['status'])))

            click.echo()
        except AttributeError:
            click.echo("\nCheck your permissions or your API keys\n")
        except resterrors.ForbiddenError:
            click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")
    else:
        click.echo("\n*** To see group membership use: navi agent groups --gid <group id> ***\n")
        try:
            click.echo("\n{:45s} {:40s} {:10}".format("Group Name", "Group UUID", "Group ID"))
            click.echo("-" * 150)

            group_list = tio.agent_groups.list()

            for group in group_list:
                click.echo("{:45s} {:40s} {:10}".format(str(group['name']),
                                                        str(group['uuid']), str(group['id'])))

            click.echo()
        except AttributeError:
            click.echo("\nCheck your permissions or your API keys\n")
        except resterrors.ForbiddenError:
            click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display Target Groups")
def target_groups():
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
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


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
            lic_data = cur.fetchall()

            click.echo("{:40s} {:65s} {}".format("Asset UUID", "Full Qualified Domain Name", "Licensed Date"))
            click.echo("-" * 150)
            click.echo()
            count = 0
            for asset in lic_data:
                count += 1
                asset_uuid = asset[0]
                fqdn = asset[1]
                licensed_date = asset[2]
                click.echo("{:40s} {:65s} {}".format(str(asset_uuid), str(fqdn), licensed_date))
        click.echo("\nTotal: {}".format(count))
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display Tags Information")
def tags():
    try:
        click.echo("\n{:55s} {:55s} {}".format("Category", "  Value", "  Value UUID"))
        click.echo("-" * 150)
        for tag_values in tio.tags.list():
            try:
                tag_value = tag_values['value']
                val_uuid = tag_values['uuid']
            except KeyError:
                tag_value = "Value Not Set Yet"
                val_uuid = "NO Value set"
            click.echo("{:55s} : {:55s} {}".format(textwrap.shorten(str(tag_values['category_name']), width=55),
                                                   textwrap.shorten(str(tag_value), width=55),
                                                   str(val_uuid)))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


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
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


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
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display the current Navi Version")
def version():
    click.echo("\nCurrent Navi Version: {}\n".format(navi_version()))


@info.command(help="Display User group information")
@click.option('--membership', required=True, default='', help="Display Users that apart of a particular "
                                                              "user group using the user group ID")
def user_groups(membership):
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
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@info.command(help="Display All Credentials, including Type and Credential UUID")
def credentials():
    try:

        click.echo("\n{:25s} {:25s} {:25s} {:25s} {:40s}".format("Credential Name", "Created By",
                                                                 "Credential Type", "Category", "Credential UUID"))
        click.echo("-" * 150)

        for cred in tio.credentials.list():
            creator = cred['created_by']['display_name']
            cred_name = cred['name']
            cred_type = cred['type']['name']
            cred_uuid = cred['uuid']
            category = cred['category']['name']
            click.echo("{:25s} {:25s} {:25s} {:25s} {:40s}".format(textwrap.shorten(cred_name, width=25),
                                                                   textwrap.shorten(creator, width=25),
                                                                   textwrap.shorten(cred_type, width=25),
                                                                   textwrap.shorten(category, width=25),
                                                                   textwrap.shorten(cred_uuid, width=40)))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


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
        click.echo("{:40s} {:15s} {:10s} {:60s} {:10s} {}".format("\nAsset Export UUID", "Created Date", "Status",
                                                                  "Export Filter Used",  "Chunk Size", "Total"))
        click.echo('-' * 150)

        for export in export_data['exports']:
            compare_time = export['created']
            newtime = arrow.Arrow.fromtimestamp(compare_time)

            if compare_time > time_frame:
                export_uuid = export['uuid']
                export_status = export['status']
                export_chunk_size = export['num_assets_per_chunk']
                export_filter = str(export['filters'])
                export_total_chunks = export['total_chunks']

                click.echo("{:39s} {:15s} {:10s} {:60s} {:10d} {}".format(export_uuid,
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
    auth_info = request_data("GET", "/users/{}/authorizations".format(uid))

    click.echo("\n{:45} {:20} {:20} {:20} {}".format("Account_UUID", "API Permitted", "Password Permitted",
                                                     "SAML Permitted", "User_UUID"))
    click.echo("-" * 150)

    click.echo("{:45} {:20} {:20} {:20} {}".format(str(auth_info['account_uuid']),
                                                   str(auth_info['api_permitted']),
                                                   str(auth_info['password_permitted']),
                                                   str(auth_info['saml_permitted']),
                                                   str(auth_info['user_uuid'])))

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
        except resterrors.ForbiddenError:
            click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")
    else:
        click.echo("\nYou must use '-scan' or '-policy'")


@info.command(help="Display completed Audit files and Audit information")
@click.option('--audit_name', default=None, help="Display all of the Assets with completed Audits "
                                                 "for the Given Audit name")
@click.option('--asset_uuid', default=None, help="Display all compliance findings for a given Asset UUID")
def audits(audit_name, asset_uuid):
    try:
        if audit_name and asset_uuid:
            audit_data = db_query("SELECT asset_uuid, check_name, status FROM compliance where audit_file='{}' "
                                  "and asset_uuid='{}';".format(audit_name, asset_uuid))

            click.echo("{:45} {:85} {}".format("\nAsset UUID", " Check Name", " Status"))
            click.echo("-" * 150)
            click.echo()
            for finding in audit_data:
                click.echo("{:45} {:85} {}".format(textwrap.shorten(str(finding[0]), width=45),
                                                   textwrap.shorten(str(finding[1]), width=85),
                                                   finding[2]))
            click.echo()

        elif audit_name:
            audit_data = db_query("SELECT asset_uuid, check_name, status FROM compliance "
                                  "where audit_file='{}';".format(audit_name))

            click.echo("{:45} {:85} {}".format("\nAsset UUID", " Check Name", " Status"))
            click.echo("-" * 150)
            click.echo()
            for finding in audit_data:
                click.echo("{:45} {:85} {}".format(textwrap.shorten(str(finding[0]), width=45),
                                                   textwrap.shorten(str(finding[1]), width=85),
                                                   finding[2]))
            click.echo()

        elif asset_uuid:
            finding_data = db_query("SELECT asset_uuid, check_name, status FROM compliance "
                                    "where asset_uuid='{}';".format(asset_uuid))

            click.echo("{:45} {:85} {}".format("\nAsset UUID", " Check Name", " Status"))
            click.echo("-" * 150)
            click.echo()
            for finding in finding_data:
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

            for names in compliance_list:
                click.echo(names[0])

            click.echo()
    except TypeError:
        click.echo("\nCheck your permissions or your API keys\n")


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
    plugin_count = 0
    try:
        rows = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns "
                        "LEFT JOIN assets ON asset_uuid = uuid where plugin_id=%s" % pid)

        click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
        click.echo("-" * 150)

        for row in rows:
            plugin_count += 1
            try:
                click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(pid), row[0],
                                                                  textwrap.shorten(str(row[2]), 46),
                                                                  row[1], row[3]))
            except AttributeError:
                pass

        click.echo("\nTotal: {}\n".format(plugin_count))
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@explore.group(help="Discover assets with Open ports, Running containers and more")
def data():
    pass


@data.command(help="Show Navi table counts or prgama table_info outputs")
@click.option("--table", default=None, help="Get Table column names and types")
def db_info(table):
    if table:
        db_data = db_query("pragma table_info({})".format(table))
        pprint.pprint(db_data)
    else:
        grab_data_info()


@data.command(help="Find Assets where a plugin fired using the plugin ID")
@click.argument('plugin_id')
@click.option('--out', default=None, help='Find Assets based on the text in the output')
@click.option('-regexp', is_flag=True, help='Use a regular expression to search plugin output')
def plugin(plugin_id, out, regexp):
    if not str.isdigit(plugin_id):
        click.echo("You didn't enter a number")
        exit()
    else:
        try:
            plugin_count = 0
            if out:
                click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address",
                                                                    "FQDN", "UUID", "Network UUID"))
                click.echo("-" * 150)
                # Search output with REGEXP enabled
                if regexp:
                    plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON "
                                           "asset_uuid = uuid "
                                           "where plugin_id='{}' and output REGEXP '{}';".format(plugin_id, out))
                # Search output for general text
                else:
                    plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON "
                                           "asset_uuid = uuid "
                                           "where plugin_id='{}' and output LIKE '%{}%';".format(plugin_id, out))

                # Not everything has a FQDN; Catch errors.
                for row in plugin_data:
                    plugin_count += 1
                    try:
                        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(plugin_id), row[0],
                                                                          textwrap.shorten(str(row[2]), 46),
                                                                          row[1], row[3]))
                    except AttributeError:
                        pass
                click.echo("\nTotal {}\n".format(plugin_count))
            else:
                find_by_plugin(plugin_id)

        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")


@data.command(help="Find Assets that have a given CVE iD")
@click.argument('cve_id')
def cve(cve_id):

    if len(cve_id) < 10:
        click.echo("\nThis is likely not a CVE...Try again...\n")

    elif "CVE" not in cve_id:
        click.echo("\nYou must have 'CVE' in your CVE string. EX: CVE-1111-2222\n")

    else:
        click.echo("\n{:8s} {:>8} {:16s} {:40s} {:38s} {}".format("Plugin", "EPSS", "IP Address",
                                                                  "FQDN", "UUID", "Network UUID"))
        click.echo("-" * 150)

        plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, plugin_id, network from vulns LEFT JOIN "
                               "assets ON asset_uuid = uuid where cves LIKE '%" + cve_id + "%';")

        for row in plugin_data:
            try:
                fqdn = row[2]
            except IndexError:
                fqdn = " "

            try:
                epss_data_raw = db_query("select epss_value from epss where cve='{}'".format(cve_id))
                epss_data = str(epss_data_raw[0][0])
            except IndexError:
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
        except IndexError:
            fqdn = " "
        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[3], row[0],
                                                          textwrap.shorten(fqdn, 46), row[1], row[4]))

    click.echo()


@data.command(help="Find Assets where Text was found in the output of any plugin")
@click.argument('out_put')
@click.option("-regexp", is_flag=True, help="Use a regular expression instead of a text search")
def output(out_put, regexp):
    plugin_count = 0
    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    if regexp:
        plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network, plugin_id from vulns LEFT JOIN"
                               " assets ON asset_uuid = uuid where output REGEXP '{}';".format(str(out_put)))
    else:
        plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network, plugin_id from vulns LEFT JOIN"
                               " assets ON asset_uuid = uuid where output LIKE '%{}%';".format(str(out_put)))

    for row in plugin_data:
        try:
            plugin_count += 1
            click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[4], row[0],
                                                              textwrap.shorten(row[2], 46),
                                                              row[1], row[3]))
        except AttributeError:
            pass

    click.echo("\nTotal: {}\n".format(plugin_count))


@data.command(help="Find Docker Hosts using plugin 93561")
def docker():
    click.echo("\nSearching for RUNNING docker containers...\n")
    find_by_plugin(str(93561))


@data.command(help="Find Potential Web Apps using plugin 1442 and 22964")
def webapp():
    try:
        click.echo("\nPotential Web Applications Report\n")

        rows = db_query("SELECT output, asset_uuid, asset_ip, network FROM vulns LEFT JOIN"
                        " assets ON asset_uuid = uuid where plugin_id ='12053';")

        for row in rows:
            host = row[0].split()
            final_host = host[3][:-1]
            web_uuid = row[1]

            click.echo("*" * 50)
            click.echo("Asset IP: {}".format(row[2]))
            click.echo("Asset UUID: {}".format(row[1]))
            click.echo("Network UUID: {}".format(row[3]))
            click.echo("*" * 50)

            new_row = db_query("SELECT output, port FROM vulns "
                               "where plugin_id ='22964' and asset_uuid='{}';".format(web_uuid))
            click.echo("\nWeb Apps Found")
            click.echo("-" * 14)

            for service in new_row:
                if "web" in service[0]:
                    if "through" in service[0]:
                        click.echo("https://{}:{}".format(final_host, service[1]))
                    else:
                        click.echo("http://{}:{}".format(final_host, service[1]))

            doc_row = db_query("SELECT output, port FROM vulns "
                               "where plugin_id ='93561' and asset_uuid='{}';".format(web_uuid))

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
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@data.command(help="Find Assets with Credential Issues using plugin 104410")
def creds():
    click.echo("\nBelow are the Assets that have had Credential issues\n")
    find_by_plugin(104410)


@data.command(help="Find Assets that took longer than a given set of minutes to complete")
@click.argument('minute')
def scantime(minute):

    click.echo("\n*** Below are the assets that took longer than {} minutes to scan ***".format(str(minute)))

    scantime_data = db_query("SELECT asset_ip, asset_uuid, scan_started, last_found, "
                             "scan_uuid, output from vulns where plugin_id='19506';")

    try:
        click.echo("\n{:16s} {:40s} {:25s} {:25s} {}".format("Asset IP", "Asset UUID",
                                                             "Started", "Finished", "Scan UUID"))
        click.echo("-" * 150)
        for vulns in scantime_data:
            plugin_dict = {}
            plugin_output = vulns[5]

            # split the output by return
            parsed_output = plugin_output.split("\n")

            for info_line in parsed_output:
                try:
                    new_split = info_line.split(" : ")
                    plugin_dict[new_split[0]] = new_split[1]

                except IndexError:
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
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@data.command(help="Find Assets that have a vulnerability on a particular port")
@click.argument('open_port')
def port(open_port):
    try:
        port_data = db_query("SELECT plugin_id, asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN "
                             "assets ON asset_uuid = uuid where port={};".format(open_port))

        try:
            click.echo("\nThe Following assets had Open ports found by various plugins")
            click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address",
                                                                "FQDN", "UUID", "Network UUID"))
            click.echo("-" * 150)

            for vuln in port_data:
                try:
                    fqdn = vuln[3]
                except IndexError:
                    fqdn = " "

                click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(vuln[0]), vuln[1],
                                                                  textwrap.shorten(fqdn, 46),
                                                                  vuln[2], vuln[4]))

            click.echo()
        except ValueError:
            pass
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@data.command(help="Find Assets using a custom SQL query.")
@click.argument('statement')
def query(statement):
    query_data = db_query(statement)
    pprint.pprint(query_data)


@data.command(help="Find Assets where a plugin fired with TEXT found in a plugin name")
@click.argument('plugin_name')
@click.option("-regexp", is_flag=True, help="Use a regular expression instead of aa text search")
def name(plugin_name, regexp):
    plugin_count = 0
    if regexp:
        plugin_data = db_query("SELECT asset_ip, asset_uuid, plugin_name, "
                               "plugin_id from vulns where plugin_name REGEXP '{}';".format(plugin_name))
    else:
        plugin_data = db_query("SELECT asset_ip, asset_uuid, plugin_name, "
                               "plugin_id from vulns where plugin_name LIKE '%{}%';".format(plugin_name))

    click.echo("\nThe Following assets had '{}' in the Plugin Name".format(plugin_name))
    click.echo("\n{:8s} {:20} {:45} {:70} ".format("Plugin", "IP address", "UUID", "Plugin Name"))
    click.echo("-" * 150)

    for vulns in plugin_data:
        plugin_count += 1
        click.echo("{:8s} {:20} {:45} {:70}".format(vulns[3], vulns[0], str(vulns[1]),
                                                    textwrap.shorten(str(vulns[2]), 65)))

    click.echo("\nTotal: {}\n".format(plugin_count))


@data.command(help="Find Assets that have a Cross Reference Type and/or ID")
@click.argument('xref')
@click.option("--xid", "--xref-id", default='', help="Specify a Cross Reference ID")
@click.option("-regexp", is_flag=True, help="Use A regular expression to find a "
                                            "specific in a Cross Reference")
def xrefs(xref, xid, regexp):
    try:
        plugin_count = 0
        click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
        click.echo("-" * 150)

        if xid:
            xref_data = db_query("select plugin_id, asset_ip, fqdn, asset_uuid, network, xrefs from vulns LEFT JOIN"
                                 " assets ON asset_uuid = uuid where xrefs "
                                 "LIKE '%{}%' AND xrefs LIKE '%{}%'".format(xref, xid))

        else:
            if regexp:
                xref_data = db_query("select plugin_id, asset_ip, fqdn, asset_uuid, network, xrefs from vulns LEFT JOIN"
                                     " assets ON asset_uuid = uuid where xrefs REGEXP '{}'".format(xref))
            else:
                xref_data = db_query("select plugin_id, asset_ip, fqdn, asset_uuid, network, xrefs from vulns LEFT JOIN"
                                     " assets ON asset_uuid = uuid where xrefs LIKE '%{}%'".format(xref))

        for row in xref_data:
            try:
                plugin_count += 1
                click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[0], row[1],
                                                                  textwrap.shorten(str(row[2]), 46),
                                                                  row[3], row[4]))
            except AttributeError:
                pass

        click.echo("\nTotal: {}\n".format(plugin_count))
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


def plugin_by_ip(ipaddr, plugin_id):
    try:
        if len(ipaddr) < 17:
            rows = db_query("SELECT output, cves, score, state, xrefs from vulns where "
                            "asset_ip=\"%s\" and plugin_id=%s" % (ipaddr, plugin_id))
        else:
            rows = db_query("SELECT output, cves, score, state, xrefs from vulns where "
                            "asset_uuid=\"%s\" and plugin_id=%s" % (ipaddr, plugin_id))

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
                    for cve_id in eval(plug[1]):
                        database = r"navi.db"
                        conn = new_db_connection(database)
                        with conn:
                            cur = conn.cursor()

                            cur.execute("select epss_value from epss where cve='{}'".format(cve_id))
                            epss_value = cur.fetchall()
                            epss_list.append(eval(epss_value[0][0]))
                            total += total + eval(epss_value[0][0])

                    average = total/len(epss_list)
                    top = max(epss_list)
                    click.echo("{:>15} {:>15} {:>15}".format("EPSS Average", "EPSS Max", "EPSS Total"))
                    click.echo("-" * 80)
                    click.echo("{:>15} {:>15} {:>15}".format(average, top, total))
                except IndexError:
                    pass
                except KeyError:
                    pass
                except TypeError:
                    pass
        click.echo()
    except IndexError:
        click.echo("No information found for this plugin")
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


def vulns_by_uuid(vulns_uuid):
    try:
        vuln_data = db_query("select plugin_id, plugin_name, plugin_family, port, protocol, "
                             "severity, state from vulns "
                             "where asset_uuid='{}' and severity !='info';".format(vulns_uuid))

        click.echo("\n{:10s} {:70s} {:35s} {:10s} {:6s} {:6s} {}".format("Plugin", "Plugin Name",
                                                                         "Plugin Family", "state",
                                                                         "Port", "Proto", "Severity"))
        click.echo("-"*150)

        for vuln in vuln_data:
            plugin_id = vuln[0]
            plugin_name = vuln[1]
            plugin_family = vuln[2]
            vuln_port = vuln[3]
            protocol = vuln[4]
            severity = vuln[5]
            state = vuln[6]
            click.echo("{:10s} {:70s} {:35s} {:10s} {:6s} {:6s} {}".format(plugin_id,
                                                                           textwrap.shorten(plugin_name, 70),
                                                                           textwrap.shorten(plugin_family, 35),
                                                                           state, vuln_port, protocol, severity))
        click.echo("")
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


def get_attributes(attr_uuid):
    attr_data = request_data('GET', '/api/v3/assets/{}/attributes'.format(attr_uuid))
    return attr_data


def info_by_uuid(info_uuid):
    try:
        info_data = db_query("select plugin_id, plugin_name, plugin_family, port, protocol, severity from "
                             "vulns where asset_uuid='{}' and severity == 'info';".format(info_uuid))

        click.echo("\n{:10s} {:90s} {:25s} {:6s} {:6s} {}".format("Plugin", "Plugin Name", "Plugin Family",
                                                                  "Port", "Proto", "Severity"))
        click.echo("-"*150)

        for vuln in info_data:
            plugin_id = vuln[0]
            plugin_name = vuln[1]
            plugin_family = vuln[2]
            vuln_port = vuln[3]
            protocol = vuln[4]
            severity = vuln[5]
            click.echo("{:10s} {:90s} {:25s} {:6s} {:6s} {}".format(plugin_id, plugin_name, plugin_family,
                                                                    vuln_port, protocol, severity))
        click.echo("")
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


def cves_by_uuid(cve_uuid):

    try:
        cve_data = db_query("select plugin_id, cves from vulns where asset_uuid='{}' and cves !=' ';".format(cve_uuid))

        click.echo("\n{:10s} {:90} {:>15} {:>15} {:>15}".format("Plugin", "CVEs", "Avg EPSS",
                                                                "Total EPSS", "Top EPSS"))
        click.echo("-"*150)

        for vuln in cve_data:
            plugin_id = vuln[0]
            cves = vuln[1]
            try:
                total = 0
                epss_list = []

                for cve_id in eval(cves):
                    database = r"navi.db"
                    conn = new_db_connection(database)
                    with conn:
                        cur = conn.cursor()

                        cur.execute("select epss_value from epss where cve='{}'".format(cve_id))
                        epss_value = cur.fetchall()
                        epss_list.append(eval(epss_value[0][0]))
                        total += total + eval(epss_value[0][0])

                average = total/len(epss_list)
                top = max(epss_list)
                click.echo("{:10s} {:90} {:15} {:15} {:15}".format(plugin_id, textwrap.shorten(cves, 90),
                                                                   average, total, top))
            except IndexError:
                average = "No EPSS"
                total = "No EPSS"
                top = "No EPSS"
                click.echo("{:10s} {:90} {:>15} {:>15} {:>15}".format(plugin_id, textwrap.shorten(cves, 90),
                                                                      average, total, top))
    except IndexError:
        click.echo("Something went wrong")
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@explore.command(help="Get Asset details based on IP or UUID")
@click.argument('ipaddr')
@click.option('--plugin_id', '--plugin', default='', help='Find Details on a particular plugin ID')
@click.option('-p', '-patch', is_flag=True, help='Patch Information - 66334')
@click.option('-t', '-tracert', is_flag=True, help='Trace Route - 10287')
@click.option('-o', '-processes', is_flag=True, help='Process Information - 70329')
@click.option('-c', '-connections', is_flag=True, help='Connection Information - 64582')
@click.option('-s', '-services', is_flag=True, help='Services Running - 22964')
@click.option('-r', '-firewall', is_flag=True, help='Local Firewall Rules - 56310')
@click.option('-patches', is_flag=True, help='Missing Patches - 38153')
@click.option('-d', is_flag=True, help="Scan Detail: 19506 plugin output")
@click.option('-apps', '-software', is_flag=True, help="Find software installed on Unix(22869) "
                                                       "of windows(20811) hosts")
@click.option('-e', '-exploit', is_flag=True, help="Display Solution, Description for each Exploit")
@click.option('-critical', is_flag=True, help="Display Plugin Output for each Critical Vuln")
@click.option('-details', is_flag=True, help="Details on an Asset: IP, UUID, Vulns, etc")
@click.option('-vulns', is_flag=True, help="Display all vulnerabilities and their plugin IDs")
@click.option('-informational', '-info', is_flag=True, help="Display all info plugins and their IDs")
@click.option('-cves', is_flag=True, help="Display all cves found on the asset")
@click.option('-compliance', '-audits', is_flag=True, help="Display all Compliance info for a "
                                                           "given asset UUID")
def uuid(ipaddr, plugin_id, p, t, o, c, s, r, patches, d, apps, e, critical, details, vulns,
         informational, cves, compliance):

    if d:
        click.echo('\nScan Detail')
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(19506))

    elif p:
        click.echo("\nPatch Information")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(66334))

    elif t:
        click.echo("\nTrace Route Info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(10287))

    elif o:
        click.echo("\nProcess Info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(70329))
        plugin_by_ip(ipaddr, str(110483))

    elif patches:
        click.echo("\nMissing Patches")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(38153))
        plugin_by_ip(ipaddr, str(66334))

        click.echo("\nLast Reboot")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(56468))

    elif c:
        click.echo("\nConnection info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(64582))

    elif s:
        try:
            if len(ipaddr) < 17:
                service_data = db_query("SELECT output, port from vulns "
                                        "where asset_ip=\"%s\" and plugin_id='22964'" % ipaddr)
            else:
                service_data = db_query("SELECT output, port from vulns "
                                        "where asset_uuid=\"%s\" and plugin_id='22964'" % ipaddr)

            for plugins in service_data:
                plugin_output = plugins[0]
                plugin_port = plugins[1]
                click.echo("\n{} {}".format(str(plugin_output), str(plugin_port)))
            click.echo()
        except IndexError:
            click.echo("No information for plugin 22964")
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    elif r:
        click.echo("Local Firewall Info")
        click.echo("-" * 15)
        plugin_by_ip(ipaddr, str(56310))
        plugin_by_ip(ipaddr, str(61797))

    elif apps:
        try:
            plugin_by_ip(ipaddr, str(22869))
            plugin_by_ip(ipaddr, str(20811))
        except IndexError:
            click.echo("No Software found")
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    elif e:
        try:
            if len(ipaddr) < 17:
                intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
                exploit_data = set(intial_data)
            else:
                exploit_data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))

            for asset in exploit_data:
                asset_id = asset[0]

                click.echo("\nExploitable Details for : {}\n".format(ipaddr))

                vuln_data = tio.workbenches.asset_vulns(asset_id,
                                                        ("plugin.attributes.exploit_available", "eq", "true"), age=90)

                for plugins in vuln_data:
                    plugin_id = plugins['plugin_id']

                    plugin_data = tio.plugins.plugin_details(plugin_id)

                    click.echo("\n----Exploit Info----")
                    click.echo(plugin_data['name'])
                    click.echo()
                    for attribute in plugin_data['attributes']:

                        if attribute['attribute_name'] == 'cve':
                            cve_id = attribute['attribute_value']
                            click.echo("CVE ID : " + cve_id)

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
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    elif critical:
        try:
            if len(ipaddr) < 17:

                intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
                critical_data = set(intial_data)
            else:
                critical_data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))

            for asset in critical_data:
                asset_id = asset[0]
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
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    elif details:
        if len(ipaddr) < 17:
            intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
            detail_data = set(intial_data)
        else:
            detail_data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))

        try:
            for asset in detail_data:
                asset_data = tio.workbenches.asset_info(str(asset[0]))

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
                        for tag in asset_data['tags']:
                            click.echo("{} : {}".format(tag["tag_key"], tag['tag_value']))
                    except KeyError:
                        pass
                    try:
                        click.echo("\nCustom Attributes:")
                        click.echo("-" * 15)
                        for attr in get_attributes(ipaddr)['attributes']:
                            click.echo("{} : {}".format(attr['name'], attr['value']))

                    except KeyError:
                        pass
                    # This needs to be rewritten to avoid the workbench

                    click.echo("\nVulnerability Counts")
                    click.echo("-" * 15)

                    asset_info = tio.workbenches.asset_info(asset_id)

                    for severity in asset_info['counts']['vulnerabilities']['severities']:
                        click.echo("{} : {}".format(severity["name"], severity["count"]))

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
        except IndexError:
            click.echo("\nWorkbench data couldn't be received, this could mean the asset UUID or IP doesn't exist "
                       "or was recently deleted.\n")
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    elif vulns:
        try:
            if len(ipaddr) < 17:
                intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
                vulns_data = set(intial_data)
                for asset in vulns_data:
                    click.echo("\nAsset UUID: {}".format(ipaddr))
                    click.echo("Asset IP: {}".format(ipaddr))
                    click.echo("-" * 26)
                    vulns_by_uuid(asset[0])
            else:
                vulns_data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))
                click.echo("\nAsset UUID: {}".format(ipaddr))
                click.echo("Asset IP: {}".format(vulns_data[0]))
                click.echo("-" * 26)
                vulns_by_uuid(ipaddr)
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    elif cves:
        try:
            if len(ipaddr) < 17:
                intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
                cve_data = set(intial_data)

                for asset in cve_data:
                    click.echo("\nAsset UUID: {}".format(asset[0]))
                    click.echo("Asset IP: {}".format(ipaddr))
                    click.echo("-" * 26)
                    cves_by_uuid(asset[0])
            else:
                click.echo("\nAsset UUID: {}".format(ipaddr))
                click.echo("-" * 26)
                cves_by_uuid(ipaddr)
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    elif informational:
        try:
            if len(ipaddr) < 17:
                intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
                info_data = set(intial_data)

                for asset in info_data:
                    click.echo("\nAsset UUID: {}".format(asset[0]))
                    click.echo("Asset IP: {}".format(ipaddr))
                    click.echo("-" * 26)
                    info_by_uuid(asset[0])
            else:
                info_data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))
                click.echo("\nAsset UUID: {}".format(ipaddr))
                click.echo("Asset IP: {}".format(info_data[0]))
                click.echo("-" * 26)
                info_by_uuid(ipaddr)
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    elif plugin_id:
        plugin_by_ip(ipaddr, plugin_id)

    elif compliance:
        try:
            if len(ipaddr) > 16:
                compliance_data = db_query("SELECT check_name, status, audit_file from compliance "
                                           "where asset_uuid='{}';".format(ipaddr))
                click.echo("{:84} {:8} {}".format("Check Name", "Status", "Audit File"))
                click.echo("-" * 150)
                for finding in compliance_data:
                    check_name = finding[0]
                    finding_status = finding[1]
                    audit_file = finding[2]
                    click.echo("{:85} {:8} {}".format(textwrap.shorten(check_name, width=80), finding_status,
                                                      textwrap.shorten(audit_file, width=60)))
            else:
                click.echo("\nCompliance info requires a UUID\n\n"
                           "For simplicity I pulled the UUID(s) with this IP\nPlease "
                           "re-run your command using one of the below UUIDs")
                uuid_data = db_query("SELECT asset_uuid, asset_hostname "
                                     "from vulns where asset_uuid='{}';".format(ipaddr))

                click.echo("{:45}{}".format("UUID", "FQDN"))
                click.echo("-" * 150)
                for address in uuid_data:
                    click.echo("{:45}{}".format(address[0], address[1]))
                click.echo()
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    else:
        click.echo("\nYou need to select an option.  use '--help' for options.\n\n")


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
                api_data = request_data('POST', url, params=params, payload=payload)
            else:
                api_data = request_data('POST', url, params=params)
        else:
            api_data = request_data('GET', url, params=params)

        if not raw:
            pprint.pprint(api_data)
        else:
            click.echo(api_data)

    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@data.command(help="Display stats on Software")
@click.option('-missing', is_flag=True, help="Display assets missing software enumeration")
@click.option('-stats', is_flag=True, help="Display General Stats")
@click.option('--greater_than', '--gt', default=None,
              help="Display Software installed Greater than or equal to the number entered")
@click.option('--less_than', '--lt', default=None,
              help="Display Software installed less than or equal to the number entered")
def software(missing, stats, greater_than, less_than):
    try:
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
                asset_uuid = str(asset[1])
                exposure_score = str(asset[4])
                acr = str(asset[3])

                click.echo("{:16} {:80} {:6} {:6} {}".format(ipv4,
                                                             textwrap.shorten(fqdn, width=80),
                                                             exposure_score, acr, asset_uuid))
            click.echo()

        elif stats:
            display_stats()

        elif greater_than:
            try:
                click.echo()
                click.echo("*"*50)
                click.echo("Below is the Software found {} times or more".format(greater_than))
                click.echo("*" * 50)
                all_data = db_query("select * from software;")
                click.echo("{:125} {}".format("\nSoftware Package Name", "Install Count"))
                click.echo('-' * 150)
                for wares in all_data:
                    length = len(eval(wares[0]))
                    if int(length) >= int(greater_than):
                        click.echo("{:125} {}".format(wares[1], len(eval(wares[0]))))
            except IndexError:
                click.echo("\nRun navi config software generate\n Or check your input\n")
            click.echo()

        elif less_than:
            try:
                click.echo("*" * 50)
                click.echo("Below is the Software found {} times or less".format(less_than))
                click.echo("*" * 50)
                all_data = db_query("select * from software;")
                click.echo("{:125} {}".format("\nSoftware Package Name", "Install Count"))
                click.echo('-' * 150)
                for wares in all_data:
                    length = len(eval(wares[0]))
                    if int(length) <= int(less_than):
                        click.echo("{:125} {}".format(wares[1], len(eval(wares[0]))))
            except IndexError:
                click.echo("\nRun navi update software Generate\n Or check your input\n")
            click.echo()

        else:
            click.echo("\nYou may want to select an option.  use '--help' for options. Here are the stats:\n\n")
            display_stats()
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@data.command(help="Display all Vulnerability Routes by Application or OS")
@click.option("--route_id", default=None, help="View/Validate the Route by Route ID")
@click.option("-exp", "-export", is_flag=True, help="Export All routes(What Navi displays)")
def route(exp, route_id):
    try:
        start = time.time()
        if route_id:

            route_info = db_query("select plugin_list from vuln_route where route_id ='{}'".format(route_id))

            work = str(route_info[0][0]).replace("[", "(").replace("]", ")")

            vuln_data = db_query("select plugins.plugin_id, plugins.name, plugins.vpr_score, "
                                 "zipper.epss_value, vulns.asset_uuid from plugins "
                                 "left join zipper on zipper.plugin_id = plugins.plugin_id "
                                 "left join vulns on plugins.plugin_id = vulns.plugin_id "
                                 "where plugins.plugin_id in {} and plugins.severity !='info' "
                                 "order by plugins.vpr_score DESC;".format(work))

            click.echo("{:8} {:10} {:70} {:10} {:10} {}".format("Route ID", "Plugin ID", "Plugin Name", "VPR Score",
                                                                "EPSS", "Asset UUID"))
            click.echo("-" * 150)
            click.echo()
            record_count = 0
            for path in vuln_data:
                try:
                    record_count += 1
                    epss_score = path[3]
                except TypeError:
                    epss_score = "NO SCORE"

                click.echo("{:8} {:10} {:70} {:10} {:10} {}".format(route_id, str(path[0]),
                                                                    textwrap.shorten(str(path[1]),
                                                                    width=70), str(path[2]),
                                                                    str(epss_score), str(path[4])))
            end = time.time()
            total = end - start
            click.echo("Query took: {} for {} records".format(total, record_count))

        else:
            display_routes()

            if exp:
                query_export("select * From vuln_route;", "Navi_routes")
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@data.command(help="Display All paths found")
@click.option("--route_id", default=None, help="View/Validate the Route by Route ID")
@click.option("--plugin_id", default=None, help="Export All routes(What Navi displays)")
def paths(plugin_id, route_id):
    try:
        if route_id:
            route_info = db_query("select plugin_list from vuln_route where route_id='{}'".format(route_id))

            work = str(route_info[0][0]).replace("[", "(").replace("]", ")")
            vuln_paths = db_query("select * from vuln_paths where plugin_id in {};".format(work))

        elif plugin_id:
            vuln_paths = db_query("select * from vuln_paths where plugin_id='{}';".format(plugin_id))
        else:
            vuln_paths = db_query("select * from vuln_paths;")

        display_paths(vuln_paths)
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@info.command(help="Display TONE Objects")
@click.option("--c", default=None,help="TONE tag Category name")
@click.option("--v", default=None, help="TONE tag Value name")
@click.option("-d","-details", is_flag=True, help="Get Tenable One Tag Details")
@click.option("-a", "-assets", is_flag=True, help="Get Tenable One assets in a given Tag")
def tone(c, v, a, d):
    from .tone_tag_helper import tag_value_exists, get_all_tags
    if c:
        if v:
            get_tag_id = tag_value_exists(c, v)

            if get_tag_id == 'no':
                click.echo("\nTag does not exist; I was not able to locate the Tag ID.  "
                           "If you just created it, give it 90 seconds and retry\n")
                exit()
            else:
                tagdata = request_data("GET", "/api/v1/t1/tags/{}".format(get_tag_id))

                if a:
                    click.echo("{:37s} {:50} {:25} {:7} {}".format("Asset ID/UUID", "FQDNs",
                                                                   "IPv4s", "ACR", "Sources"))
                    click.echo(150 * "-")
                    for asset_data in tagdata['assets']:
                        grab_asset_id = db_query("select asset_id, fqdns, ipv4_addresses, acr, sources "
                                                 "from tone_assets where asset_id='{}';".format(asset_data))

                        asset_id = grab_asset_id[0][0]
                        try:
                            fqnds = grab_asset_id[0][1]
                        except IndexError:
                            fqnds = "NONE"

                        try:
                            ipv4 = grab_asset_id[0][2]
                        except IndexError:
                            ipv4 = "NONE"

                        try:
                            acrs = grab_asset_id[0][3]
                        except IndexError:
                            acrs = "NONE"
                        try:
                            sources = grab_asset_id[0][4]
                        except IndexError:
                            sources = "None?"

                        click.echo("{:37s} {:50} {:25} {:7} {}".format(str(asset_id),
                                                                            textwrap.shorten(fqnds, 50),
                                                                            textwrap.shorten(ipv4, 25), acrs,
                                                                            textwrap.shorten(sources, 40)))

                elif d:
                    creator = tagdata['creator']['username']
                    created_at = tagdata['tag_created_at']
                    description = tagdata['tag_description']
                    total_weaknesses = tagdata['total_weakness_count']
                    critical = tagdata['weakness_severity_counts']['critical']
                    high = tagdata['weakness_severity_counts']['high']
                    medium = tagdata['weakness_severity_counts']['medium']
                    low = tagdata['weakness_severity_counts']['low']

                    click.echo("Tag Details for - {} : {}\n".format(c, v))
                    click.echo(50 * "*")
                    click.echo("\nDescription: {}\n".format(description))
                    click.echo(50 * "*")
                    click.echo("\nCreator: {}".format(creator))
                    click.echo("Created at: {}\n".format(created_at))
                    click.echo(50 * "*")
                    click.echo("\nTotal Weakness Count: {}".format(total_weaknesses))
                    click.echo(30 * "-")
                    click.echo("Critical: {}".format(critical))
                    click.echo("High: {}".format(high))
                    click.echo("Medium: {}".format(medium))
                    click.echo("Low: {}\n\n".format(low))
                else:
                    click.echo("\nYou need to use '-d' for details, '-a' for asset information.\n")
        else:
            click.echo("\nYou need a value if you want tag information\n")

    else:
        get_all_tags()

