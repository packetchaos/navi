import click
import time
from .api_wrapper import request_data
from .scanners import nessus_scanners
from .database import new_db_connection
from .error_msg import error_msg
from .licensed_count import get_licensed
from sqlite3 import Error


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
def display(scanners, users, exclusions, containers, logs, running, scans, nnm, assets, policies, connectors, agroup, status, agents, webapp, tgroup, licensed, tags, categories, smtp):

    if scanners:
        nessus_scanners()

    if users:
        try:
            data = request_data('GET', '/users')
            print("\nUser Name".ljust(35), "Login email")
            print("----------".ljust(34), "----------")
            for user in data["users"]:
                print(user["name"].ljust(30), " - ", user["username"])
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
            print("Container Name".ljust(35) + " | " + "Repository ID".ljust(35) + " | " + "Tag".ljust(15) + " | " + "Docker ID".ljust(15) + " | " + "# of Vulns".ljust(10))
            print("-----------------------------------------------------------------------------------")
            try:
                for images in data["items"]:
                    print(str(images["name"]).ljust(35) + " | " + str(images["repoName"]).ljust(35) + " | " + str(images["tag"]).ljust(15) + " | " + str(images["imageHash"]).ljust(15) + " | " + str(images["numberOfVulns"]).ljust(25))
            except KeyError:
                pass
        except Exception as E:
            error_msg(E)

    if logs:
        try:
            data = request_data('GET', '/audit-log/v1/events')
            for log in data['events']:
                received = log['received']
                action = log['action']
                actor = log['actor']['name']

                print("Date : " + received)
                print("-------------------")
                print(action, '\n', actor, '\n')
        except Exception as E:
            error_msg(E)

    if running:
        try:
            data = request_data('GET', '/scans')
            run = 0
            for scan in data['scans']:
                if scan['status'] == "running":
                    run = run + 1
                    name = scan['name']
                    scan_id = scan['id']
                    current_status = scan['status']

                    click.echo("\nScan Name : " + name)
                    print("Scan ID : " + str(scan_id))
                    print("Current status : " + current_status)
                    print("-----------------\n")
            if run == 0:
                print("No running scans")
        except Exception as E:
            error_msg(E)

    if scans:
        try:
            data = request_data('GET', '/scans')

            for scan in data['scans']:
                name = scan['name']
                scan_id = scan['id']
                scan_status = scan['status']

                print("Scan Name : " + name)
                print("Scan ID : " + str(scan_id))
                print("Current status : " + scan_status)
                print("-----------------\n")

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
            data = request_data('GET', '/workbenches/assets/?date_range=30')
            asset_list = []
            for x in range(len(data["assets"])):
                for y in range(len(data["assets"][x]["ipv4"])):
                    ip = data["assets"][x]["ipv4"][y]

                    while ip not in asset_list:
                        asset_list.append(ip)
            asset_list.sort()
            print("\nIn the last 30 days, I found " + str(len(asset_list)) + " IP Addresess. See below:\n")
            for z in range(len(asset_list)):
                print(asset_list[z])
            print()
        except Exception as E:
            error_msg(E)

    if policies:
        try:
            data = request_data('GET', '/policies')
            print()
            for policy in data['policies']:
                print(policy['name'])
                print(policy['description'])
                print('Template ID : ', policy['template_uuid'], '\n')
        except Exception as E:
            error_msg(E)

    if connectors:
        try:
            data = request_data('GET', '/settings/connectors')
            for conn in data["connectors"]:
                print("\nConnector Type: ", conn['type'])
                print("Connector Name: ", conn['name'])
                print("Connector ID: ", conn['id'])
                print("----------------------------")
                print("Schedule: ", conn['schedule']['value'], conn['schedule']['units'])
                try:
                    print("Last Sync Time", conn['last_sync_time'])

                except KeyError:
                    pass
                print("Status Message: ", conn['status_message'])
                print("------------------------------------------")
        except Exception as E:
            error_msg(E)

    if agroup:
        try:
            data = request_data('GET', '/access-groups')
            for group in data["access_groups"]:
                print("\nAccess Group Name: ", group['name'])
                print("Access Group ID: ", group['id'])
                try:
                    print("Created by: ", group['created_by_name'])

                    print("---------")
                    print("Created at: ", group['created_at'])
                    print("Updated at: ", group['updated_at'])
                    print("----------------------")
                except KeyError:
                    pass
                print("Current Status: ", group['status'])
                print("Percent Complete: ", group['processing_percent_complete'])
                print("---------------------------------")
                print("Rules")
                print("-----------------------------------------")
                details = request_data('GET', '/access-groups/'+str(group['id']))
                try:
                    for rule in details['rules']:
                        print(rule['type'], rule['operator'], rule['terms'])
                except KeyError:
                    pass
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
            print("Contianer Name : ", session_data["container_name"])
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
        try:
            data = request_data('GET', '/scanners/104490/agents')
            print("\b Agent information is pulled from the US Cloud Scanner\b")
            for agent in data['agents']:
                last_connect = agent['last_connect']
                last_connect_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_connect))

                try:
                    last_scanned = agent['last_scanned']
                    last_scanned_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_scanned))
                except KeyError:
                    # I assume if we can't pull as scanned time, it doesn't exist
                    last_scanned_time = "Agent has not Been Scanned"

                print("Agent Name : ", agent['name'])
                print("-----------------------------")
                print("Agent IP : ", agent['ip'])
                print("Last Connected :", last_connect_time)
                print("Last Scanned : ", last_scanned_time)
                print("Agent Status : ", agent['status'], '\n')
                print("Groups")
                print("-------------")

                try:
                    for group in agent['groups']:
                        print(group['name'])
                except KeyError:
                    pass
                print()
        except Exception as E:
            error_msg(E)

    if webapp:
        try:
            data = request_data('GET', '/scans')

            for scan in data['scans']:
                if scan['type'] == 'webapp':
                    name = scan['name']
                    scan_id = scan['id']
                    scan_status = scan['status']

                    print("Scan Name : " + name)
                    print("Scan ID : " + str(scan_id))
                    print("Current status : " + scan_status)
                    print("-----------------\n")

        except Exception as E:
            error_msg(E)

    if tgroup:
        data = request_data('GET', '/target-groups')
        try:
            for targets in data['target_groups']:
                print()
                print("Name : ", targets['name'])
                print("Owner : ", targets['owner'])
                print("Target Group ID : ", targets['id'])
                print("Members : ", targets['members'])
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

            print("IP Address".ljust(15), "Full Qualified Domain Name".ljust(65), "Licensed Date")
            print("-".ljust(91, "-"))
            print()
            for asset in data:
                ipv4 = asset[0]
                fqdn = asset[1]
                licensed_date = asset[2]
                print(str(ipv4).ljust(15), str(fqdn).ljust(65), licensed_date)
        print()

    if tags:
        data = request_data('GET', '/tags/values')
        print("\nTags".ljust(35), "Value".ljust(35), "Value UUID")
        print('-'.rjust(92, '-'), "\n")
        for tag_values in data['values']:
            try:
                tag_value = tag_values['value']
                uuid = tag_values['uuid']
            except KeyError:
                tag_value = "Value Not Set Yet"
                uuid = "NO Value set"
            print(str(tag_values['category_name']).ljust(30), " : ", str(tag_value).ljust(35), str(uuid).ljust(25))
        print()

    if categories:
        data = request_data('GET', '/tags/categories')
        print("\nTag Categories".ljust(35), "Category UUID")
        print('-'.rjust(50, '-'), "\n")
        for cats in data['categories']:

            category_name = cats['name']
            category_uuid = cats['uuid']

            print(str(category_name).ljust(30), " : ", str(category_uuid).ljust(25))
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
