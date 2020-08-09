import click
import time
from .api_wrapper import request_data
from .scanners import nessus_scanners
from .database import new_db_connection
from .error_msg import error_msg
from .licensed_count import get_licensed
from sqlite3 import Error
import textwrap


@click.command(help="Display or Print information found in Tenable.io")
@click.option('-scanners', is_flag=True, help="List all of the Scanners")
@click.option('-users', is_flag=True, help="List all of the Users")
@click.option('-exclusions', is_flag=True, help="List all Exclusions")
@click.option('-containers', is_flag=True, help="List all containers and their Vulnerability  Scores")
@click.option('-logs', is_flag=True, help="List The actor and the action in the log file")
@click.option('-running', is_flag=True, help="List the running Scans")
@click.option('-scans', is_flag=True, help="List all Scans")
@click.option('-nnm', is_flag=True, help="Nessus Network Monitor assets and their vulnerability scores")
@click.option('-assets', is_flag=True, help="Assets found in the last 30 days")
@click.option('-policies', is_flag=True, help="Scan Policies")
@click.option('-connectors', is_flag=True, help="List Connector Details and Status")
@click.option('-agroup', is_flag=True, help="List Access Groups and Status")
@click.option('-status', is_flag=True, help="Print T.io Status and Account info")
@click.option('-agents', is_flag=True, help="Print Agent information")
@click.option('-webapp', is_flag=True, help='Print Web App Scans')
@click.option('-tgroup', is_flag=True, help='Print Target Groups')
@click.option('-licensed', is_flag=True, help='Print License information')
@click.option('-tags', is_flag=True, help='Print Tag Categories and values')
@click.option('-categories', is_flag=True, help='Print all of the Tag Categories and their UUIDs')
@click.option('-smtp', is_flag=True, help="Print your smtp information")
@click.option('-cloud', is_flag=True, help="Print Cloud assets found in the last 30 days by the connectors")
@click.option('-networks', is_flag=True, help="Print Network IDs")
@click.option('-version', is_flag=True, help="Display current version of Navi")
@click.option('-usergroup', is_flag=True, help="Display current User groups")
@click.option('--membership', default='', help="Display users of a certain group using the Group ID")
def display(scanners, users, exclusions, containers, logs, running, scans, nnm, assets, policies, connectors, agroup,
            status, agents, webapp, tgroup, licensed, tags, categories, smtp, cloud, networks, version, usergroup, membership):

    if scanners:
        nessus_scanners()

    if users:
        try:
            data = request_data('GET', '/users')
            print("\nUser Name".ljust(35), "Login email".ljust(40), "User UUID".ljust(40), "User ID".ljust(10), "Enabled?")
            print("-" * 150)
            for user in data["users"]:
                print(str(user["name"]).ljust(34), str(user["username"]).ljust(40), str(user['uuid']).ljust(40), str(user['id']).ljust(10), str(user["enabled"]))
            print()

        except Exception as E:
            error_msg(E)

    if exclusions:
        try:
            data = request_data('GET', '/exclusions')
            for x in data["exclusions"]:
                print("\nExclusion Name : ", x["name"], '\n')
                print(x["members"], '\n')

        except KeyError:
            print("No Exclusions Set, or there could be an issue with your API keys")

    if containers:
        try:
            data = request_data('GET', '/container-security/api/v2/images?limit=1000')
            print("\nContainer Name".ljust(35), "Repository ID".ljust(35), "Tag".ljust(15), "Docker ID".ljust(15), "# of Vulns".ljust(10))
            print("-" * 125)
            try:
                for images in data["items"]:
                    print(str(images["name"]).ljust(35), str(images["repoName"]).ljust(35), str(images["tag"]).ljust(15), str(images["imageHash"]).ljust(15), str(images["numberOfVulns"]).ljust(25))
            except KeyError:
                pass
            print()
        except Exception as E:
            error_msg(E)

    if logs:
        try:
            data = request_data('GET', '/audit-log/v1/events')
            print("\nEvent Date".ljust(24), "Action Taken".ljust(30), "User".ljust(30))
            print("-" * 100)
            for log in data['events']:
                received = log['received']
                action = log['action']
                actor = log['actor']['name']
                print(str(received).ljust(24), str(action).ljust(30), str(actor))

        except Exception as E:
            error_msg(E)
        print()

    if running:
        try:
            data = request_data('GET', '/scans')
            run = 0
            print("\nScan Name".ljust(61), "Scan ID".ljust(10), "Status".ljust(30))
            print("-" * 100)
            for scan in data['scans']:
                if scan['status'] == "running":
                    run = run + 1
                    name = scan['name']
                    scan_id = scan['id']
                    current_status = scan['status']

                    print(str(name).ljust(60), str(scan_id).ljust(10), str(current_status))
            print()

            if run == 0:
                print("No running scans")
        except Exception as E:
            error_msg(E)

    if scans:
        print()
        print("*" * 40)
        print("This endpoint is extremely limited. 1 to 2 calls per min")
        print("If you get a 429 error, wait a minute and try again")
        print("*" * 40)
        try:
            data = request_data('GET', '/scans')
            print("\nScan Name".ljust(61), "Scan ID".ljust(10), "Status".ljust(30))
            print("-" * 100)
            for scan in data['scans']:
                name = scan['name']
                scan_id = scan['id']
                scan_status = scan['status']
                print(str(name).ljust(60), str(scan_id).ljust(10), str(scan_status))
            print()

        except Exception as E:
            error_msg(E)

    if nnm:
        try:
            # dynamically find the PVS sensor
            nnm_data = request_data('GET', '/scans')

            for scan in nnm_data["scans"]:

                if str(scan["type"]) == "pvs":
                    nnm_id = scan["id"]
                    try:
                        data = request_data('GET', '/scans/' + str(nnm_id) + '/')
                        if len(data["hosts"]) != 0:
                            print("Here are the assets and their scores last found by Nessus Network Monitor")
                            print("   IP Address     : Score")
                            print("----------------")

                            for host in data["hosts"]:
                                print(str(host["hostname"]) + " :  " + str(host["score"]))
                            print()
                    except KeyError:
                        pass
        except Exception as E:
            error_msg(E)

    if assets:
        try:
            data = request_data('GET', '/workbenches/assets/?date_range=30') #, params=asset_limit)

            print("\nBelow are the assets found in the last 30 days")
            print("\nIP Address(es)".ljust(35), "FQDN(s)".ljust(65), "Exposure Score".ljust(15), "Sources")
            print("-" * 120)
            for asset in data["assets"]:
                sources = []
                for source in asset["sources"]:
                    sources.append(source['name'])

                print(str(asset["ipv4"]).ljust(36), str(asset["fqdn"]).ljust(64), str(asset["exposure_score"]).ljust(15), sources)

        except Exception as E:
            error_msg(E)

    if policies:
        try:
            data = request_data('GET', '/policies')
            print("\nPolicy Name".ljust(41), "Description".ljust(61), "Template ID")
            print("-" * 100)
            for policy in data['policies']:
                print(str(policy['name']).ljust(40), str(policy['description']).ljust(60), policy['template_uuid'] )
            print()
        except Exception as E:
            error_msg(E)

    if connectors:
        try:
            data = request_data('GET', '/settings/connectors')
            print("\nType".ljust(11), "Connector Name".ljust(40), "Connnector ID".ljust(40), "Last Sync".ljust(30), "Schedule ")
            print("-" * 150)
            for conn in data["connectors"]:
                schedule = str(conn['schedule']['value']) + " " + str(conn['schedule']['units'])
                try:
                    last_sync = conn['last_sync_time']

                except KeyError:
                    last_sync = "Hasn't synced"
                print(str(conn['type']).ljust(10), str(conn['name']).ljust(40), str(conn['id']).ljust(40), last_sync.ljust(30), schedule)
        except Exception as E:
            error_msg(E)
        print()

    if agroup:
        rules = "Not Rule Based"
        try:
            data = request_data('GET', '/access-groups')
            print("\nGroup Name".ljust(26), "Group ID".ljust(40), "Last Updated".ljust(25), "Rules")
            print("-" * 120)
            for group in data["access_groups"]:
                try:
                    updated = group['updated_at']
                except KeyError:
                    updated = "Not Updated"
                details = request_data('GET', '/access-groups/'+str(group['id']))

                try:
                    for rule in details['rules']:
                        rules = str(rule['terms'])
                except KeyError:
                    rules = "Not Rule Based"
                print(str(group['name']).ljust(25), str(group['id']).ljust(40), str(updated).ljust(25), textwrap.shorten(rules, width=60))
            print()
        except Exception as E:
            error_msg(E)

    if status:
        try:
            data = request_data('GET', "/server/properties")
            session_data = request_data('GET', "/session")

            print("\nTenable IO Information")
            print("-----------------------")
            print("Container ID : ", session_data["container_id"])
            print("Container UUID :", session_data["container_uuid"])
            print("Container Name : ", session_data["container_name"])
            print("Site ID :", data["analytics"]["site_id"])
            print("Region : ", data["region"])

            print("\nLicense information")
            print("--------------------")
            print("Licensed Assets : ", get_licensed())
            print("Agents Used : ", data["license"]["agents"])
            print("Expiration Date : ", data["license"]["expiration_date"])
            print("Scanners Used : ", data["license"]["scanners"])
            print("Users : ", data["license"]["users"])
            print("\nEnabled Apps")
            print("---------")
            print()
            for key in data["license"]["apps"]:
                print(key)
                print("-----")
                try:
                    print("Expiration: ", data["license"]["apps"][key]["expiration_date"])

                except KeyError:
                    pass
                print("Mode: ", data["license"]["apps"][key]["mode"])
                print()

        except Exception as E:
            error_msg(E)

    if agents:
        querystring = {"limit": "5000"}
        try:
            data = request_data('GET', '/scanners/1/agents', params=querystring)
            print("\nAgent Name".ljust(46), "IP Address".ljust(20), "Last Connect Time".ljust(20), "Last Scanned Time".ljust(20), "Status".ljust(10), "Groups")
            print("-" * 140)
            for agent in data['agents']:
                last_connect = agent['last_connect']
                last_connect_time = time.strftime("%b %d %H:%M:%S", time.localtime(last_connect))

                try:
                    last_scanned = agent['last_scanned']
                    last_scanned_time = time.strftime("%b %d %H:%M:%S", time.localtime(last_scanned))
                except KeyError:
                    # I assume if we can't pull as scanned time, it doesn't exist
                    last_scanned_time = "Not Scanned"
                groups = ''
                try:
                    for group in agent['groups']:
                        groups = groups + ", " + group['name']
                except KeyError:
                    pass
                print(str(agent['name']).ljust(45), str(agent['ip']).ljust(20), str(last_connect_time).ljust(20),
                      str(last_scanned_time).ljust(20), str(agent['status']).ljust(10), str(groups[1:]))
        except Exception as E:
            error_msg(E)
        print()

    if webapp:
        print()
        print("*" * 40)
        print("This is using the V1 and Was 1.0 endpoints")
        print("use the 'navi was --help' to see what is available for v2")
        print("*" * 40)
        try:
            data = request_data('GET', '/scans')
            print("\nScan Name".ljust(61), "Scan ID".ljust(10), "Status".ljust(30))
            print("-" * 100)
            for scan in data['scans']:
                if scan['type'] == 'webapp':
                    name = scan['name']
                    scan_id = scan['id']
                    scan_status = scan['status']
                    print(str(name).ljust(60), str(scan_id).ljust(10), str(scan_status))
            print()

        except Exception as E:
            error_msg(E)

    if tgroup:
        print()
        print("*" * 40)
        print("Target Groups are going to be retired use the Migration script to covert them to tags")
        print("https://github.com/packetchaos/tio_automation/blob/master/migrate_target_groups.py")
        print("*" * 40)
        data = request_data('GET', '/target-groups')
        print("\nTarge Group Name".ljust(41), "TG ID".ljust(10), "Owner".ljust(30), "Members")
        print("-" * 100)
        try:
            for targets in data['target_groups']:
                mem = targets['members']
                print(str(targets['name']).ljust(40), str(targets['id']).ljust(10), str(targets['owner']).ljust(30), textwrap.shorten(mem, width=60))
            print()
        except Exception as E:
            error_msg(E)

    if licensed:
        print("\nLicensed Count : ", get_licensed())
        print()
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT ip_address, fqdn, last_licensed_scan_date from assets where last_licensed_scan_date !=' ';")
            data = cur.fetchall()

            print("IP Address".ljust(20), "Full Qualified Domain Name".ljust(65), "Licensed Date")
            print("-" * 120)
            print()
            for asset in data:
                ipv4 = asset[0]
                fqdn = asset[1]
                licensed_date = asset[2]
                # Don't display Web applications in this output
                if ipv4 != " ":
                    print(str(ipv4).ljust(20), str(fqdn).ljust(65), licensed_date)
        print()

    if tags:
        data = request_data('GET', '/tags/values')
        print("\nTags".ljust(33), "Value".ljust(35), "Value UUID")
        print('-'.rjust(92, '-'), "\n")
        for tag_values in data['values']:
            try:
                tag_value = tag_values['value']
                uuid = tag_values['uuid']
            except KeyError:
                tag_value = "Value Not Set Yet"
                uuid = "NO Value set"
            print(str(tag_values['category_name']).rjust(30), ":", str(tag_value).ljust(35), str(uuid).ljust(25))
        print()

    if categories:
        data = request_data('GET', '/tags/categories')
        print("\nTag Categories".ljust(31), "Category UUID")
        print('-'.rjust(50, '-'), "\n")
        for cats in data['categories']:

            category_name = cats['name']
            category_uuid = cats['uuid']

            print(str(category_name).ljust(30), str(category_uuid).ljust(25))
        print()

    if smtp:
        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT server, port, from_email from smtp;")
                data = cur.fetchall()
                for settings in data:
                    print("\nYour email server: {}".format(settings[0]))
                    print("The email port is: {}".format(settings[1]))
                    print("Your email is: {}\n".format(settings[2]))
        except Error as E:
            print("\nYou have no SMTP information saved.\n")
            print("Error: ", E, "\n")

    if cloud:
        query = {"date_range": "30", "filter.0.filter": "sources", "filter.0.quality": "set-has", "filter.0.value": "AWS",
                 "filter.1.filter": "sources", "filter.1.quality": "set-has", "filter.1.value": "AZURE",
                 "filter.2.filter": "sources", "filter.2.quality": "set-has", "filter.2.value": "GCP", "filter.search_type":"or"}
        data = request_data('GET', '/workbenches/assets', params=query)
        print("\nSource".ljust(11), "IP".ljust(15), "FQDN".ljust(45), "UUID".ljust(40), "First seen")
        print("-" * 150)
        for assets in data['assets']:
            for source in assets['sources']:
                if source['name'] != 'NESSUS_SCAN':
                    asset_ip = assets['ipv4'][0]
                    uuid = assets['id']
                    try:
                        asset_fqdn = assets['fqdn'][0]
                    except IndexError:
                        asset_fqdn = "NO FQDN found"

                    print(source['name'].ljust(10), asset_ip.ljust(15), asset_fqdn.ljust(45),uuid.ljust(40), source['first_seen'])
        print()

    if networks:
        try:
            data = request_data('GET', '/networks')
            print("\nNetwork Name".ljust(26), "# of Scanners".ljust(16), "UUID")
            print("-" * 100)
            for network in data['networks']:
                print(network['name'].ljust(25), str(network['scanner_count']).ljust(15), network['uuid'])
        except Exception as E:
            error_msg(E)
        print()

    if version:
        print("\nNavi Version 5.3.0\n")

    if usergroup:
        data = request_data("GET", "/groups")
        print("\nGroup Name".ljust(35), "Group ID".ljust(10), "Group UUID".ljust(40), "User Count".ljust(10))
        print("-" * 150)
        for ugroup in data["groups"]:
            print(str(ugroup['name']).ljust(35), str(ugroup['id']).ljust(10), str(ugroup['uuid']).ljust(40), str(ugroup['user_count']))
        print()

    if membership != '':
        data = request_data("GET", '/groups/' + str(membership) + "/users")
        print("\nUser Name".ljust(35), "Login email".ljust(40), "User UUID".ljust(40), "User ID".ljust(10), "Enabled?")
        print("-" * 150)
        for user in data["users"]:
            print(str(user["name"]).ljust(34), str(user["username"]).ljust(40), str(user['uuid']).ljust(40), str(user['id']).ljust(10), str(user["enabled"]))
        print()
