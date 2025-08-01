import click
import pprint
import getpass
import datetime
import textwrap
from .th_asset_export import asset_export
from .th_vuln_export import vuln_export
from .th_compliance_export import compliance_export
from .fixed_export import fixed_export
from .was_export import grab_scans
from .epss import update_navi_with_epss, zipper_epss_plugin
from .dbconfig import (create_keys_table, create_diff_table, create_assets_table, create_vulns_table,
                       create_compliance_table, create_passwords_table, create_software_table,
                       create_certs_table, create_plugins_table, create_agents_table, create_vuln_route_table,
                       create_vuln_path_table, create_sla_table)
from .database import (new_db_connection, create_table, drop_tables, db_query, insert_software, insert_vuln_router,
                       insert_certificates, insert_vuln_paths)
from .fixed_export import calculate_sla, reset_sla, print_sla
from .api_wrapper import request_data, tenb_connection, request_no_response
from .agent_to_db import download_agent_data
from restfly import errors as resterrors

tio = tenb_connection()


def parse_22869(soft_dict):
    software_data = db_query("select output, asset_uuid from vulns where plugin_id='22869'")
    for data in software_data:
        asset_uuid = data[1]
        for pkg in str(data[0]).splitlines():
            pkg_name = str(pkg.split("|"))
            if "packages installed" not in pkg_name:
                string_list = str(eval(pkg_name)[0]).split()
                try:
                    if len(string_list[0]) == 2:
                        new_name = "{}-{}".format(string_list[1], string_list[2])
                        if new_name not in soft_dict:
                            soft_dict[new_name] = [asset_uuid]
                        else:
                            soft_dict[new_name].append(asset_uuid)
                    else:
                        new_name = str(string_list[0]).strip()
                        if new_name not in soft_dict:
                            soft_dict[new_name] = [asset_uuid]
                        else:
                            soft_dict[new_name].append(asset_uuid)

                except IndexError:
                    pass


def parse_20811(soft_dict):
    software_data = db_query("select output, asset_uuid from vulns where plugin_id='20811'")
    for data in software_data:
        asset_uuid = data[1]
        for pkg in data:
            new_string = str(pkg).splitlines()
            my_list = eval(str(new_string))
            for item in my_list:
                if "The following software" not in item:
                    if "installed" in item:
                        new_item = item.split(" [installed")
                        try:
                            if new_item[0] not in soft_dict:
                                soft_dict[new_item[0]] = [asset_uuid]
                            else:
                                soft_dict[new_item[0]].append(asset_uuid)
                        except TypeError:
                            pass


def parse_83991(soft_dict):
    software_data = db_query("select output, asset_uuid from vulns where plugin_id='83991'")
    for host in software_data:
        for pkg in host:
            pkg_string = str(pkg).splitlines()
            new_list = eval(str(pkg_string))
            for item in new_list[:-1]:
                if "  Location" not in item:
                    if "Error" not in item:
                        if item not in soft_dict:
                            soft_dict[item] = [host[-1]]
                        else:
                            soft_dict[item].append(host[-1])


def threads_check(threads):
    if threads != 20:  # Limit the amount of threads to avoid issues
        click.echo("\nUsing {} thread(s) at your request".format(threads))
        if threads not in range(1, 21):
            click.echo("Enter a value between 1 and 20")
            exit()


def find_target_group(tg_name):
    data = request_data("GET", '/target-groups')
    group_id = 0
    for target_groups in data['target_groups']:
        try:
            if target_groups['name'] == tg_name:
                group_id = target_groups['id']
        except KeyError:
            pass
    return group_id


def create_target_group(target_name, tg_list):
    # Check to see if the Target group exists
    group_id = find_target_group(target_name)

    # Target group API takes a string of IPs. We will start the string here.
    target_string = ""

    # Check to see if tg_list is a string
    string_test = isinstance(tg_list, str)

    # turn the list into a string separated by a comma
    if not string_test:
        for ips in tg_list:
            target_string = target_string + str(ips) + ","
    else:
        target_string = tg_list

    if not tg_list:
        click.echo("\nYour request returned zero results\nAs a result, nothing happened\n")
        exit()

    click.echo("\nThese are the IPs that will be added to the target Group: {}".format(target_name))
    click.echo(tg_list)
    click.echo()

    if group_id != 0:
        # Update current Target Group
        payload = {"name": target_name, "members": target_string, "type": "system"}
        request_data("PUT", '/target-groups/' + str(group_id), payload=payload)
    else:
        # Create a New Target Group
        payload = {"name": target_name, "members": str(target_string), "type": "system",
                   "acls": [{"type": "default", "permissions": 64}]}
        request_data("POST", '/target-groups', payload=payload)


def get_scanner_id(scanner_name):
    try:
        # Receive name, convert to lower-case, then look up the scanner's ID
        for scanner in tio.scanners.list():
            if str(scanner_name).lower() == str(scanner['name']).lower():
                return scanner['uuid']
            else:
                return 'NONE'
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


def get_network_id(network_name):
    try:
        # Receive network name, convert to lower-case, then look up the network's uuid
        for net in tio.networks.list():
            if network_name.lower() == str(net['name']).lower():
                return net['uuid']
        return 'None'
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


def check_agroup_exists(aname):
    try:
        rvalue = 'no'
        for access_groups in tio.access_groups.list():
            if str(access_groups['name']).lower() == str(aname).lower():
                rvalue = access_groups['id']
        return rvalue
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


def create_user(username, password, permission, name, email):
    payload = {"username": "{}".format(str(username)), "password": str(password), "permissions": permission,
               "name": name, "email": "{}".format(str(email))}

    data = request_no_response("POST", "/users", payload=payload)

    return data


def enable_disable_user(user_id, answer):
    if answer == "enable":
        payload = {"enabled": True}
    else:
        payload = {"enabled": False}

    request_no_response("PUT", "/users/" + str(user_id) + "/enabled", payload=payload)


def change_auth_settings(user_id, payload):
    request_no_response("PUT", "/users/{}/authorizations".format(user_id), payload=payload)


def get_user_id(username):
    data = request_data("GET", "/users")
    user_id = 0
    user_uuid = 0
    for u in data["users"]:
        if username.lower() == u["username"]:
            user_id = u["id"]
            user_uuid = u['uuid']
    return user_id, user_uuid


def create_group(group_name):
    payload = {'name': group_name}
    # Using the Delete request because of an API Return issue.
    data = request_no_response("POST", "/groups", payload=payload)

    return data


def add_users(user_id, group_id):
    add_url = "/groups/{}/users/{}".format(group_id, user_id)
    # Using the Delete request because of an API Return issue.
    request_no_response("POST", add_url)


def remove_user(user_id, group_id):
    remove_url = "/groups/{}/users/{}".format(group_id, user_id)
    # Using the Delete request because of an API Return issue.
    request_no_response("DELETE", remove_url)


def get_group_id(group_name):
    data = request_data("GET", "/groups")
    group_id = 0
    group_uuid = 0
    for groups in data["groups"]:

        if group_name == groups["name"]:
            group_id = groups["id"]
            group_uuid = groups['uuid']
    return group_id, group_uuid


def create_permission(name, tag_name, uuid, perm_string, perm_type, subject_type):
    payload = {
        "actions": ["{}".format(perm_string)],
        "objects": [
            {
                "name": name,
                "type": perm_type,
                "uuid": str(uuid)
            }
        ],
        "subjects": [{"type": subject_type}],
        "name": "{} : [{}]".format(tag_name, perm_string)
    }
    response = request_data("POST", "/api/v3/access-control/permissions", payload=payload)
    return response


def create_granular_permission(tag_name, uuid, perm_list, perm_type, subject_type, subject_name, subject_uuid):
    payload = {
        "actions": perm_list,
        "objects": [
            {
                "name": tag_name,
                "type": perm_type,
                "uuid": str(uuid)
            }
        ],
        "subjects": [{"name": subject_name, "type": subject_type, "uuid": subject_uuid}],
        "name": "{} : {}".format(tag_name, perm_list)
    }
    response = request_data("POST", "/api/v3/access-control/permissions", payload=payload)
    return response


def grab_can_use_tags():
    # This script supports the Migrate command which adds CanUse to ALLUsers
    data = request_data("GET", "/api/v3/access-control/permissions")

    list_of_tag_uuids = []
    # Filter on just permissions
    for perms in data['permissions']:
        # Need to search for CanUse
        if 'CanUse' in str(perms['actions']):

            # Extract all Tag UUIDs
            for tag in perms['objects']:
                try:
                    if tag['type'] == 'Tag':
                        list_of_tag_uuids.append(tag['uuid'])
                except KeyError:
                    pass
    return list_of_tag_uuids


def update_software():
    database = r'navi.db'
    new_conn = new_db_connection(database)
    drop_tables(new_conn, "software")
    create_software_table()
    soft_dict = {}

    # Grab 22869 Data
    parse_22869(soft_dict)

    # Grab 20811 Data
    parse_20811(soft_dict)

    # grab 83991 Data
    parse_83991(soft_dict)

    with new_conn:
        try:

            for item in soft_dict.items():
                # Save the uuid list as a string
                new_list = [item[0], str(item[1]).strip()]
                insert_software(new_conn, new_list)
            click.echo("\nSoftware imported into a table called 'software'. Use 'navi explore data software'\n\n")
        except IndexError:
            click.echo("\nERROR: You may not have info plugins downloaded or "
                       "you do not have any authenticated assets\n\n")


def update_certificates():
    database = r"navi.db"
    cert_conn = new_db_connection(database)
    cert_conn.execute('pragma journal_mode=wal;')
    cert_conn.execute('pragma cashe_size=-10000')
    cert_conn.execute('pragma synchronous=OFF')
    click.echo("\nParsing every output for plugin 10863. This can take some time.\n"
               "\nThe data will be saved in a table named 'certs'\n\n")
    drop_tables(cert_conn, 'certs')
    create_certs_table()
    with cert_conn:
        try:
            cert_data = db_query("select asset_uuid, output from vulns where plugin_id='10863';")
            cert_dict = {}
            asset_uuid = cert_data[0][0]

            for certs in cert_data:

                first_pass = str(certs[1])
                second_pass = str(first_pass).replace("'", "")
                third_pass = str(second_pass).split("\n")

                for line in third_pass:
                    csv_list = []
                    forth_pass = str(line).split(": ")

                    try:
                        cert_dict[forth_pass[0]] = forth_pass[1]
                    except IndexError:
                        pass

                    csv_list.append(asset_uuid)

                    try:
                        csv_list.append(cert_dict['Subject Name'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Country'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['State/Province'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Locality'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Organization'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Common Name'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Issuer Name'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Organization Unit'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Serial Number'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Version'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Signature Algorithm'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Not Valid Before'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Not Valid After'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Algorithm'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Key Length'])
                    except KeyError:
                        csv_list.append(" ")

                    try:
                        csv_list.append(cert_dict['Signature Length'])
                    except KeyError:
                        csv_list.append(" ")

                insert_certificates(cert_conn, csv_list)
        except IndexError:
            click.echo("\nERROR: You may not have info plugins downloaded or "
                       "you do not have any instances of plugin 10863\n\n")


def grab_epss_today(filename):
    date_info = str(datetime.datetime.now()).split("-")
    year = date_info[0]
    month = date_info[1]
    day = date_info[2][:2]
    update_navi_with_epss(day, month, year, filename)


def grab_data_info():
    click.echo()
    try:
        vuln_count = db_query("select count(*) from vulns;")[0][0]
    except IndexError:
        vuln_count = "Needs updating - run 'navi config update vulns' "
        click.echo("\nNo data in the Vulns table\n")

    try:
        plugin_count = db_query("select count(*) from plugins;")[0][0]
    except IndexError:
        plugin_count = "Needs updating - run 'navi config update vulns' "
        click.echo("\nNo data in the plugins table\n")

    try:
        asset_count = db_query("select count(*) from assets;")[0][0]
    except IndexError:
        asset_count = "Needs updating - run 'navi config update assets' "
        click.echo("\nNo data in the assets table\n")

    try:
        tag_count = db_query("select count(*) from tags;")[0][0]
    except IndexError:
        tag_count = "Needs updating - run 'navi config update assets' "
        click.echo("\nNo data in the tags table\n")

    try:
        compliance_count = db_query("select count(*) from compliance;")[0][0]
    except IndexError:
        compliance_count = "Needs updating - run navi config update compliance' "
        click.echo("\nNo data in the compliance table\n")

    try:
        fixed_count = db_query("select count(*) from fixed;")[0][0]
    except IndexError:
        fixed_count = "Needs updating - run 'navi config update fixed' "
        click.echo("\nNo data in the fixed table\n")

    try:
        agent_count = db_query("select count(*) from agents;")[0][0]
    except IndexError:
        agent_count = "Needs updating - run 'navi config update agents'"
        click.echo("\nNo data in the agents table\n")

    try:
        cert_count = db_query("select count(*) from certs;")[0][0]
    except IndexError:
        cert_count = "Needs updating - run 'navi config certificates' "
        click.echo("\nNo data in the certs table\n")

    try:
        software_count = db_query("select count(*) from software;")[0][0]
    except IndexError:
        software_count = "Needs updating - run 'navi config software' "
        click.echo("\nNo data in the software table\n")

    try:
        application_count = db_query("select count(*) from apps;")[0][0]
    except IndexError:
        application_count = "Needs updating"
        click.echo("\nNo data in the apps table\n")

    try:
        epss_count = db_query("select count(*) from epss;")[0][0]
    except IndexError:
        epss_count = "Needs updating - run 'navi config epss'"
        click.echo("\nNo data in the epss table\n")

    try:
        path_count = db_query("select count(distinct path) from vuln_paths;")[0][0]
        total_path = db_query("select count(path) from vuln_paths;")[0][0]
    except IndexError:
        path_count = "Needs updating - run 'navi config update paths' "
        total_path = "Needs updating - run 'navi config update paths' "
        click.echo("\nNo data in the epss table\n")

    try:
        route_count = db_query("select count(*) from vuln_route;")[0][0]
    except IndexError:
        route_count = "Needs updating - run 'navi config update route' "
        click.echo("\nNo data in the epss table\n")

    click.echo("-" * 70)
    click.echo("-" * 70)
    click.echo(" " * 25 + "Database Stats")
    click.echo("-" * 70)
    click.echo("-" * 70)
    click.echo()

    click.echo("Vuln Count: {}".format(vuln_count))
    click.echo("Plugin Count: {}".format(plugin_count))
    click.echo("Asset Count: {}".format(asset_count))
    click.echo("Tag Count: {}".format(tag_count))
    click.echo("Compliance Count: {}".format(compliance_count))
    click.echo("Agent Count: {}".format(agent_count))
    click.echo("Fixed Count: {}".format(fixed_count))
    click.echo("Cert Count: {}".format(cert_count))
    click.echo("Software Count: {}".format(software_count))
    click.echo("Application Count: {}".format(application_count))
    click.echo("EPSS CVE Count: {}".format(epss_count))
    click.echo("Unique Path Count: {}".format(path_count))
    click.echo("Total Path Count: {}".format(total_path))
    click.echo("Unique Route Count: {}".format(route_count))
    click.echo("-" * 70)
    click.echo()


def display_routes():
    route_count = 0
    routes = db_query("select * from vuln_route ORDER BY total_vulns;")

    click.echo("{:8} {:30} {:20} {:70} {:15}".format("Route ID", "Application Name", "Product Type",
                                                     "Plugin ID Summary", "Total instances"))
    click.echo("-" * 150)
    click.echo()
    for path in routes:
        route_count += 1
        click.echo("{:8} {:30} {:20} {:70} {:15}".format(path[0], textwrap.shorten(path[1], width=30), path[4],
                                                         textwrap.shorten(path[2], width=70), path[3]))

    click.echo("\nTotal: {}\n".format(route_count))


def group_by_plugins():
    click.echo("\nCreating a Vulnerability Routing Table called vuln-routes\n\n")
    database = r"navi.db"
    route_conn = new_db_connection(database)
    drop_tables(route_conn, 'vuln_route')
    create_vuln_route_table()

    data = db_query("select name, plugin_id from plugins where severity !='info';")

    with route_conn:
        route_id = 0
        grouped_plugins = {}

        for name, plugin_id in data:
            parts = name.split()
            clean_second_part = str(parts[1]).replace("<", " ")
            first_part = parts[0].upper()
            second_part = clean_second_part.upper()

            # Vuln Route Data Pipeline / Transform logic
            if first_part.startswith("KB") or first_part.startswith("MS"):
                key = "Windows Updates"
            elif first_part.startswith("SECURITY"):
                key = "Internet Explorer"
            elif first_part.startswith("GIT") and second_part.startswith("FOR"):
                key = "Git for Windows"
            elif first_part.startswith(".SVN"):
                key = "HTTP"
            elif first_part.startswith("PHP"):
                key = "PHP"
            elif first_part.startswith("SSH"):
                key = "SSH"
            elif first_part.startswith("OPENJDK"):
                key = "OpenJDK"
            elif first_part.startswith("JENKINS"):
                key = "Jenkins"
            elif first_part == "DEBIAN":
                key = "Debian"
            elif "JIRA" in first_part or "JIRA" in second_part:
                key = "Atlassian Jira"
            elif first_part == "UBUNTU" or second_part == "UBUNTU":
                key = "Ubuntu"
            elif first_part.startswith("PYTHON") or second_part.startswith("PYTHON"):
                key = "Python"
            elif first_part.startswith("ESX") or second_part.startswith("ESX"):
                key = "Vmware ESXI"
            elif first_part.startswith("SSL") or first_part.startswith("TLS") or first_part.startswith("OPENSSL"):
                key = "SSH/TLS"
            elif len(parts) >= 1:
                key = f"{parts[0]} {clean_second_part}"
            else:
                key = parts[0]

            if key not in grouped_plugins:
                grouped_plugins[key] = []

            grouped_plugins[key].append(plugin_id)
        list_of_oses = []

        # grab all the OSes detected to use as our base-line
        oses = db_query("select distinct OSes from vulns;")
        for os in oses:
            new_os = os[0]
            try:
                new_list = eval(new_os)
            except:
                new_list = new_os
            # OSes is a list, so the Distinct option in sqlite doesn't dedupe everything.
            # Here I cycle through each item in the list and compare it to the current list before adding it.
            for i in new_list:
                if i not in list_of_oses:
                    list_of_oses.append(i)

        for plugin_group, plugin_ids in grouped_plugins.items():
            total = 0
            db_list = []
            first_word = plugin_group.split(" ")
            if str(first_word[0]) in str(list_of_oses):
                vuln_type = "Operating System"
            else:
                vuln_type = "Application"

            # Query to grab the total of each plugin IDs for instance total
            for plugin_inst in plugin_ids:
                plugin_count = db_query("select count(*) from vulns where plugin_id='{}'".format(plugin_inst))
                total += plugin_count[0][0]

            route_id += 1
            db_list.append(route_id)
            db_list.append(plugin_group)
            db_list.append(str(plugin_ids))
            db_list.append(total)
            db_list.append(str(vuln_type))
            insert_vuln_router(route_conn, db_list)

    click.echo("\nFinished updating the vuln_route table. Use 'navi explore data route' to view it's context\n")


def display_paths(vuln_paths):
    path_count = 0
    click.echo("{:8} {:8} {:95} {}".format("Path ID", "Plugin ID",
                                           "Path", "Asset UUID"))
    click.echo("-" * 150)
    click.echo()
    for path in vuln_paths:
        path_count += 1
        click.echo("{:8} {:8} {:95} {}".format(path[0], path[1],
                                               textwrap.shorten(path[2], width=95), path[3]))

    click.echo("\nTotal: {}\n".format(path_count))


def search_for_path():
    import re
    click.echo("\nCreating a Vulnerability Path Table called vuln-paths\n\n")
    database = r"navi.db"
    path_conn = new_db_connection(database)
    drop_tables(path_conn, 'vuln_paths')
    create_vuln_path_table()

    pattern = r'''(?ix)
                (?:                                          
                  [a-zA-Z]:\\(?:[\w\s().-]+\\)*[\w\s().-]{3,}     # Windows path with spaces, parentheses
                  |
                  (?:\.{1,2}/|/)(?:[\w.-]+/)*[\w.-]{3,}           # Unix-style paths
                )'''

    search_outputs_for_paths = db_query("select plugin_id, asset_uuid, finding_id, output "
                                        "from vulns where severity !='info' and "
                                        "plugin_name not like '%SSL Certificate%';")
    with path_conn:
        path_id = 0
        for plugin_text in search_outputs_for_paths:
            for plugin_instance in eval(str(plugin_text)):

                # search the plugin text for the path pattern
                matches = re.findall(pattern, plugin_instance)

                def is_valid_path(p):
                    stripped = p.strip()

                    # Remove trailing slash if present
                    if stripped.endswith('/'):
                        stripped = stripped[:-1]

                    # Get the last segment only (filename or last dir)
                    last_segment = stripped.split('/')[-1].split('\\')[-1]

                    # Regex: match version numbers or IPs like 1.2.3 or v1.0.0 or 192.168.0.1
                    version_or_ip_pattern = r'^(v?\d+(\.\d+){1,3}[a-z]?)$'

                    # Exclude if the last segment looks like a version or IP
                    return not re.match(version_or_ip_pattern, last_segment, re.IGNORECASE)

                filtered = [p for p in matches if is_valid_path(p)]

                for m in filtered:
                    path_list = []
                    path_id += 1

                    # Remove meta data
                    scrub_one = str(m).replace("Installed version", " ")
                    scrub_two = str(scrub_one).replace("has not been patched.", " ")
                    scrub_three = str(scrub_two).replace("Remote version", " ")
                    scrub_four = str(scrub_three).replace("Used by services", " ")
                    scrub_five = str(scrub_four).strip()

                    path_list.append(path_id)
                    path_list.append(plugin_text[0])
                    path_list.append(scrub_five)
                    path_list.append(plugin_text[1])
                    path_list.append(plugin_text[2])
                    insert_vuln_paths(path_conn, path_list)

    click.echo("\n Update finished.  Run 'navi explore data paths'\n")


@click.group(help="Configure permissions, scan-groups, users, user-groups, networks, "
                  "sla, smtp, mail, keys and update the navi database")
def config():
    pass


@config.group(help="Change Access Control Permissions")
def permissions():
    pass


@config.group(help="Perform common tasks against Agents and Agent Groups")
def agent():
    pass


@config.group(help="Enable, Disable or add users")
def user():
    pass


@config.group(help="Migrate Target Groups to Scans or Tags and Create Target Groups(Retiring soon)")
def target_group():
    pass


@config.group(help="Set, Reset and Calculate SLAs")
def sla():
    pass


@user.group(help="Create a user group or Add/remove a user from a user group")
def group():
    pass


@config.group(help="Create a new network, Change TTL in a network, move assets or scanners")
def network():
    pass


@config.command(help="Enter or Reset your Keys")
@click.option("-clear", is_flag=True, help="Display Keys in Clear Text for confirmation")
@click.option("--access_key", "--a", default="", help="Provide your Access Key")
@click.option("--secret_key", "--s", default="", help="Provide your Secret Key")
def keys(clear, access_key, secret_key):
    try:
        # create all Tables when keys are added.
        create_keys_table()
        create_diff_table()
        create_vulns_table()
        create_plugins_table()
        create_assets_table()
        create_agents_table()
        create_compliance_table()
        create_sla_table()

        # Check if the keys are empty
        if access_key == "" or secret_key == "":
            click.echo("\nHey you don't have any Keys!\n")
            if clear:
                access_key = input("Please provide your Access Key : ")
                secret_key = input("Please provide your Secret Key : ")
            else:
                access_key = getpass.getpass("Please provide your Access Key : ")
                secret_key = getpass.getpass("Please provide your Secret Key : ")

        key_dict = (access_key, secret_key)
        database = r"navi.db"
        conn = new_db_connection(database)

        with conn:
            sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
            cur = conn.cursor()
            cur.execute(sql, key_dict)

        click.echo("\nYour keys were entered successfully")
    except:
        click.echo("\nThe keys are obtained from TVm and are two strings. "
                   "If you continue to get this error delete the 'navi.db'\n\n")


@config.command(help="Enter or Overwrite your SMTP information")
@click.option("--server", default="", help="Provide the Server address ex: smtp.gmail.com")
@click.option("--port", default="", help="Enter the port your Email server uses ex: 587")
@click.option("--email", default="", help="Enter your email address")
@click.option("--password", default="", help="Enter your password")
def smtp(server, port, email, password):

    if server == "":
        server = input("Enter the Email servers address - ex: mail.gmx.com : ")

    if port == "":
        port = input("Enter the port your Email server uses - ex: 587: ")

    if email == "":
        email = input("Enter your Email Address - ex: youremail@gmx.com ")

    if password == "":
        password = getpass.getpass("Enter your email password - : ")
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        drop_tables(conn, 'smtp')

        create_smtp_table = """CREATE TABLE IF NOT EXISTS smtp (
                                server text,
                                port text,
                                email text, 
                                password text 
                                );"""
        create_table(conn, create_smtp_table)

        info = (server, port, email, password)

        with conn:
            sql = '''INSERT or IGNORE into smtp(server, port, email, password) VALUES(?,?,?,?)'''
            cur = conn.cursor()
            cur.execute(sql, info)
        click.echo("\nYour smtp information was entered successfully\n\n")
    except:
        click.echo("\nThere seems to be a db error. Check your inputs and try again or delete the navi.db\n\n")


@config.command(help="Enter a ssh service account User Name and Password")
@click.option("--username", prompt=True, help="Provide your Access Key")
@click.option("--password", prompt=True, hide_input=True, help="Provide your Secret Key")
def ssh(username, password):
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        drop_tables(conn, 'ssh')

        create_passwords_table()

        ssh_dict = (username, password)
        conn = new_db_connection(database)

        with conn:
            sql = '''INSERT or IGNORE into ssh(username, password) VALUES(?,?)'''
            cur = conn.cursor()
            cur.execute(sql, ssh_dict)

        click.echo("\nYour username and password was entered successfully\n\n")
    except:
        click.echo("\nThere seems to be a db error. Check your inputs and try again or delete the navi.db\n\n")


@sla.command(help="Overwrite your SLA information")
@click.option("--critical", default='', help="Set your Critical Vulnerability SLA")
@click.option("--high", default='', help="Set your High Vulnerability SLA")
@click.option("--medium", default='', help="Set your Medium SLA")
@click.option("--low", default='', help="Set your Low SLA")
def reset(critical, high, medium, low):
    if critical == '' and high == '' and medium == '' and low == '':
        click.echo("\nYou Entered Nothing, but chose to reset your SLA.  I'm using the Defaults for you\n")
        # Set Defaults: user could only select one
        reset_sla(7, 14, 30, 180)
        print_sla()
    else:
        if critical == '':
            critical = 7

        if high == '':
            high = 14

        if medium == '':
            medium = 30

        if low == '':
            low = 180

        reset_sla(critical, high, medium, low)
        print_sla()


@sla.command(help="Calculate SLA times")
def calculate():
    try:
        calculate_sla("total")
        calculate_sla("critical")
        calculate_sla("high")
        calculate_sla("medium")
        calculate_sla("low")
        click.echo()
    except:
        click.echo("\n You need to run `navi update fixed` first\n")


@network.command(help="Change the Asset Age Out of a network")
@click.option("--age", default='', required=True, help="Change the Asset Age Out - 90days or more")
@click.option("--net", default='', help="Enter the Network ID")
@click.option("--name", default='', help="Enter the Network name")
def change(age, net, name):
    click.echo("\nChanging the age to {}\n for the network: {}\n".format(age, name))

    if age:
        if 1 <= int(age) <= 365:
            if net:
                if name:
                    click.echo("choose net OR name, not both")
                    exit()

                if len(net) == 36:
                    network_data = request_data('GET', '/networks/' + net)
                    net_name = network_data['name']
                    payload = {"assets_ttl_days": age, "name": net_name, "description": "TTL adjusted by navi"}
                    request_data('PUT', '/networks/' + net, payload=payload)
                else:
                    click.echo("Check the UUID length")
            if name:
                payload = {"assets_ttl_days": age, "name": name, "description": "TTL adjusted by navi"}
                request_data('PUT', '/networks/{}'.format(get_network_id(name)), payload=payload)
        else:
            click.echo("Asset Age Out number must between 1 and 365")
    else:
        click.echo("Please enter a Age value")


@network.command(help="Create a new Network")
@click.option("--name", default='', required=True, help="Create a Network with the Following Name")
@click.option("--description", "--d", default='Navi Created', help="Create a description for your Network")
def new(name, description):
    try:
        click.echo("\nCreating a new network named {}\n".format(name))

        if name:
            tio.networks.create(name, description=description)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@network.command(help="Move a Scanner or Assets to a Network")
@click.option('--net', default='', required=True, help="Network Name or Network UUID")
@click.option('--scanner', default='', help="Scanner Name or Scanner UUID")
@click.option('--c', default='', help="Move Assets from This Tag Category")
@click.option('--v', default='', help="Move Assets from This Tag Value")
@click.option('--source', required=True, default='00000000-0000-0000-0000-000000000000',
              help="Source Network UUID")
@click.option('--target', default='', help="Move Assets by subnet(s)")
def move(net, scanner, c, v, source, target):
    ip_list = ""
    if scanner != '':
        # Here I just want to check to see if it is an uuid. If it's not 36 chars long, it is not an uuid.
        if len(net) != 36:
            network_id = get_network_id(net)
        else:
            network_id = net

        # Scanner UUIDs have two lengths, both over 35. This isn't bulletproof, but it's good enough for now.
        # I expect a lot from users. :)
        if len(scanner) > 35:
            # This should be an uuid.
            scanner_id = scanner
        else:
            # Let's grab the uuid
            scanner_id = get_scanner_id(scanner)
        try:
            # move the scanner
            tio.networks.assign_scanners(network_id, scanner_id)
        except resterrors.ForbiddenError:
            click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")

    if c != '' and v != '':
        # First grab all the UUIDS in the tag and put them in a list
        click.echo("\nThis feature is limited to 1999 assets; Consider using 'target' option to specify a subnet\n")
        tag_uuid_list = []
        tag_data = db_query("SELECT asset_uuid from tags where tag_key='" + c + "' and tag_value='" + v + "';")
        for uuid in tag_data:
            if uuid not in tag_uuid_list:
                tag_uuid_list.append(uuid[0])

        # then grab the Scanned IP from the vulns table using the UUID as a Key; then put the IPs in a list
        ip_list = ""

        for item in tag_uuid_list:
            ip_address = db_query("select asset_ip from vulns where asset_uuid='{}'".format(item))

            try:
                ip = ip_address[0][0]
                if ip not in ip_list:
                    ip_list = ip_list + "," + ip
            except IndexError:
                pass

    if target:
        ip_list = ip_list + "," + target

    # Current limit is 1999 assets to be moved at once
    payload = {"source": source, "destination": net, "targets": ip_list[1:]}
    request_data("POST", '/api/v2/assets/bulk-jobs/move-to-network', payload=payload)
    click.echo("\nMoving these assets \n {}".format(ip_list[1:]))


@config.command(help="Create a Scanner Group")
@click.option("--name", required=True, help="Name of Scanner Group")
def scan_group(name):
    try:
        tio.scanner_groups.create(name)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@target_group.command(help="Create a Target Group - Retiring in T.io soon")
@click.option('--name', default='Navi Created Target Group', required=True, help="Target Group Name")
@click.option('--ip', default='', help="Ip(s) or subnet(s) separated by coma")
def create(name, ip):
    if ip:
        create_target_group(name, ip)


@target_group.command(help="Migrate Target Groups to Tags or to Scan Text Targets")
@click.option('--scan', default='', help="Move Target Group Members in a given scan to the Text Target "
                                         "section of the same scan")
@click.option('-tags', is_flag=True, help="Migrate All Target Groups to Tags - "
                                          "Target Group Type : Target Group Name")
def migrate(scan, tags):
    if tags:
        tgroups = request_data('GET', '/target-groups')

        for target_groups in tgroups['target_groups']:
            member = target_groups['members']
            name = target_groups['name']
            group_type = target_groups['type']
            d = "Imported by Script"
            try:
                if name != 'Default':
                    payload = {"category_name": str(group_type), "value": str(name), "description": str(d),
                               "filters": {"asset": {"and": [{"field": "ipv4", "operator": "eq",
                                                              "value": str(member)}]}}}
                    data = request_data('POST', '/tags/values', payload=payload)

                    value_uuid = data["uuid"]
                    cat_uuid = data['category_uuid']
                    click.echo("\nI've created your new Tag - {} : {}\n".format(group_type, name))
                    click.echo("The Category UUID is : {}\n".format(cat_uuid))
                    click.echo("The Value UUID is : {}\n".format(value_uuid))
            except TypeError:
                click.echo("\nTag has already been created, or there was a name conflict\n")
                pass

    elif scan:
        def grab_tg_members():
            # Grab all members of every target group and put them into a dict for evaluation later
            tg_member_dict = {}
            member_data = request_data('GET', '/target-groups')

            for tg in member_data['target_groups']:
                tg_member = tg['members']
                tg_member_dict[tg['id']] = tg_member
            return tg_member_dict

        def get_tg_list():
            # grab the target list ID from a scan
            tgs_for_scan = []
            tg_data = request_data("GET", '/editor/scan/{}'.format(scan))
            for item in tg_data["settings"]["basic"]["inputs"]:
                if item["name"] == "Target Groups":
                    tgs_for_scan = item["default"]  # This maps each scan ID to the list of target group IDs
            return tgs_for_scan

        text_target_string = ""
        try:
            for scan_id in get_tg_list():
                text_target_string = text_target_string + ",{}".format(grab_tg_members()[scan_id])

            payload = {"settings": {
                "target_groups": [],
                "text_targets": text_target_string[1:]}}

            update_scan = request_data("PUT", "/scans/{}".format(scan), payload=payload)
            click.echo("\n{} was updated with the below targets:\n {}".format(update_scan['name'],
                                                                              text_target_string[1:]))
        except TypeError:
            exit()
        except KeyError:
            click.echo("\nScan doesn't exist or doesn't have a target group assigned\n")
    else:
        click.echo("\nYou need to select an option: --scan or -tags\n")


@config.command(help="Create an Access group Based on a Tag - DEPRECATED in T.vm")
@click.option('--name', default='', required=True, help="Choose a Name for your Access Group.")
@click.option('--c', default='', required=True, help="Tag Category name to use")
@click.option('--v', default='', required=True, help="Tag Value to use")
@click.option('--user_name', default='', help="The user you want to Assign to the Access Group - "
                                              "username@domain")
@click.option('--user_group', default='', help="The User Group you want to assign to the Access Group")
@click.option('--perm', type=click.Choice(['scan', 'view', 'scanview'], case_sensitive=False),
              required=True)
def access_group(name, c, v, user_name, user_group, perm):
    permission = []
    choice = 'none'
    perm_type = 'none'

    if user_name == '' and user_group == '':
        click.echo("\nYou Need to use '--user_name' or '--user_group' command and supply "
                   "a user or group. e.g: user@yourdomain or Linux Admins\n")
        exit()

    if user_name:
        perm_type = 'user'
        choice = user_name

    if user_group:
        perm_type = 'group'
        choice = user_group

    if perm.lower() == 'scanview':
        permission = ["CAN_VIEW", "CAN_SCAN"]

    elif perm.lower() == 'view':
        permission = ["CAN_VIEW"]

    elif perm.lower() == 'scan':
        permission = ["CAN_SCAN"]

    asset_data = db_query("SELECT tag_uuid from tags where tag_key='" + c + "' and tag_value='" + v + "';")

    # Grab the first UUID...UUIDs returned are duplicates due to the db structure
    tag_uuid = [asset_data[0][0]]

    if tag_uuid:
        payload = {"name": str(name), "access_group_type": "MANAGE_ASSETS",
                   "rules": [{"type": "tag_uuid", "operator": "set-has", "terms": tag_uuid}],
                   "principals": [{"permissions": permission, "type": perm_type, "principal_name": choice}]}

        # Check to see if the group exists
        answer = check_agroup_exists(str(name))

        try:
            # Check to see if the list has any IPs in it.
            if answer == 'no':
                new_access_group = request_data('POST', '/v2/access-groups', payload=payload)
                click.echo("\nYour Access group {} is being created now \n".format(new_access_group['name']))
                click.echo("The UUID is {} \n".format(new_access_group['id']))
            else:
                update_group = request_data('PUT', '/v2/access-groups/' + str(answer), payload=payload)
                click.echo("\nYour Access group {} is being updated now \n".format(update_group['name']))
                click.echo("The UUID is {} \n".format(update_group['id']))
        except TypeError as E:
            click.echo("\nAccess group? - Check the Username")
            click.echo(E)
    else:
        click.echo("\nYour Tag was null. Check the spelling or perform a 'navi update assets'\n")


@user.command(help="Add a User to tenable VM - User will be enabled if already exists")
@click.option("--username", "--u", default='', required=True, help="Username")
@click.option("--password", "--p", default='', required=True, help="Users password")
@click.option("--permission", "--m", default='', required=True, help="Users Permission: (16,24,32,40,64)")
@click.option("--name", "--n", default='', required=True, help="Users Name")
@click.option("--email", "--e", default='', required=True, help="Users email")
def add(username, password, permission, name, email):
    if len(password) < 11:
        click.echo("Password must be 12 chars, 1 Upper, 1 lower and 1 Special Char")
        exit()

    # Check to see has already been created
    user_id, user_uuid = get_user_id(username)

    if user_id == 0:
        # if the user doesn't exist. Create it.
        create_user(username, password, permission, name, email)
    else:
        # If the user is trying to create the user, and it already exists, Try to enable it instead
        enable_disable_user(user_id, "enable")


@user.command(help="Enable Auth settings or an Account")
@click.argument('uid')
@click.option('-account', is_flag=True, help="Enable User Account")
@click.option('-api', is_flag=True, help="Enable API Access")
@click.option('-pwd', is_flag=True, help="Enable Password Access")
@click.option('-saml', is_flag=True, help="Enable SAML Access")
def enable(uid, api, pwd, saml, account):
    payload = {"api_permitted": False, "password_permitted": False, "saml_permitted": False}
    if api:
        payload["api_permitted"] = True

    if pwd:
        payload["password_permitted"] = True

    if saml:
        payload["saml_permitted"] = True

    if api or pwd or saml:
        change_auth_settings(uid, payload)

    if account:
        enable_disable_user(uid, "enable")

    if not account and not api and not pwd and not saml:
        click.echo("\nYou need to specify an option\n\nIf you want to disable an account use the '-account' option\n")


@user.command(help="Disable a user by ID or auth settings")
@click.argument('uid')
@click.option('-account', is_flag=True, help="Enable User Account")
@click.option('-api', is_flag=True, help="Enable API Access")
@click.option('-pwd', is_flag=True, help="Enable Password Access")
@click.option('-saml', is_flag=True, help="Enable SAML Access")
def disable(uid, account, api, pwd, saml):
    payload = {"api_permitted": True, "password_permitted": True, "saml_permitted": True}

    if api:
        payload["api_permitted"] = False

    if pwd:
        payload["password_permitted"] = False

    if saml:
        payload["saml_permitted"] = False

    if api or pwd or saml:
        change_auth_settings(uid, payload)

    if account:
        enable_disable_user(uid, "disable")

    if not account and not api and not pwd and not saml:
        click.echo("\nYou need to specify an option\n\nIf you want to disable an account use the '-account' option\n")


@group.command(help="Create a new user group")
@click.option("--name", default='', required=True, help="The Name of the user group")
def create(name):
    # Check to see if the group already exists
    group_id, group_uuid = get_group_id(name)
    if group_id == 0:
        create_group(name)
    else:
        print("Your Group already exists. Here is the group id {}".format(group_id))


@group.command(help="Add a User to a user group")
@click.option("--usergroup", default='', required=True, help="The Name of the user group")
@click.option("--name", default='', required=True, help="The User Name to be added")
def add(usergroup, name):
    user_id, user_uuid = get_user_id(name)
    group_id, group_uuid = get_group_id(usergroup)
    add_users(user_id, group_id)


@group.command(help="Remove a User from a user group")
@click.option("--usergroup", default='', required=True, help="The Name of the group")
@click.option("--name", default='', required=True, help="The User Name to be removed")
def remove(usergroup, name):
    user_id, user_uuid = get_user_id(name)
    group_id, group_uuid = get_group_id(usergroup)
    remove_user(user_id, group_id)


@permissions.command(help="Change Access Control Permissions using a Tag")
@click.option('--c', default='', required=True, help="Tag Category name to use")
@click.option('--v', default='', required=True, help="Tag Value to use")
@click.option('--user_name', default='', help="The User you want to assign to the Permission")
@click.option('--user_group', default='', help="The User Group you want to assign to the Permission")
@click.option('--perm', multiple=True,
              type=click.Choice(['CanScan', 'CanView', 'CanEdit', 'CanUse'], case_sensitive=True))
@click.option('--perm_list', default='', help='Added all perms in a comma delimited string to '
                                              'support automation')
def create(c, v, user_name, user_group, perm, perm_list):
    # Create the naming format for the tag permission
    perm_name = "{},{}".format(c, v)
    try:

        tag_uuid = 0
        # Grab the Tag UUID using the value and category given
        for tag in tio.tags.list():

            tag_value = tag['value']
            tag_category = tag['category_name']
            if c == tag_category and v == tag_value:
                tag_uuid = tag['uuid']

        # Add permission by User
        if user_name:
            user_id, uuid = get_user_id(user_name)
            if perm_list:
                resp = create_granular_permission(tag_name=perm_name, uuid=tag_uuid,
                                                  perm_list=list(str(perm_list).split(",")), perm_type="Tag",
                                                  subject_type="User",
                                                  subject_name=user_name, subject_uuid=uuid)
                pprint.pprint(resp)
            else:
                resp = create_granular_permission(tag_name=perm_name, uuid=tag_uuid,
                                                  perm_list=perm, perm_type="Tag", subject_type="User",
                                                  subject_name=user_name, subject_uuid=uuid)
                pprint.pprint(resp)

        # Add permission by User Group
        elif user_group:
            group_id, uuid = get_group_id(user_group)

            if perm_list:
                resp = create_granular_permission(tag_name=perm_name, uuid=tag_uuid,
                                                  perm_list=list(str(perm_list).split(",")), perm_type="Tag",
                                                  subject_type="UserGroup",
                                                  subject_name=user_group, subject_uuid=uuid)
                pprint.pprint(resp)
            else:
                resp = create_granular_permission(tag_name=perm_name, uuid=tag_uuid,
                                                  perm_list=perm, perm_type="Tag", subject_type="UserGroup",
                                                  subject_name=user_group, subject_uuid=uuid)
                pprint.pprint(resp)
        else:
            # If no user or User group Assign it to All Users
            if perm_list:
                permission_response = create_permission(name=perm_name, tag_name=perm_name, uuid=tag_uuid,
                                                        perm_string=list(str(perm_list).split(",")), perm_type="Tag",
                                                        subject_type="AllUsers")
                pprint.pprint(permission_response)
            else:
                permission_response = create_permission(name=perm_name, tag_name=perm_name, uuid=tag_uuid,
                                                        perm_string=perm, perm_type="Tag", subject_type="AllUsers")

                pprint.pprint(permission_response)

    except IndexError:
        click.echo("\nYour Tag might be incorrect. Or you may need to update assets in navi.  "
                   "No tag UUID was returned\n")
        exit()
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@permissions.command(help='Find all Tags without Permissions and apply "CanUse" permissions to AllUsers')
def migrate():
    click.confirm("\n This script finds all tags without any permissions and creates a CANUSE permission. "
                  "Do you want to continue?\n")
    unique_ids = []
    new_list_uuids = []

    # Grab all the Tags with Can Use
    canuse_tags = grab_can_use_tags()

    # Grab all Tags and their names from the navi db
    tag_in_db = db_query("select tag_uuid, tag_key, tag_value from tags;")

    for tag in tag_in_db:
        # reduce the amount of tags uuids, since the navi db has a record for each asset:tag_uuid
        if tag[0] not in unique_ids:
            unique_ids.append(tag[0])
            # create a dict to hold the tag name and the tag uuid
            new_list_uuids.append({"{},{}".format(tag[1], tag[2]): tag[0]})

    # Loop through the list of uuids without permissions
    click.echo("\nCanUse permissions will be created for each of these tags\n")
    for uuid in new_list_uuids:
        for key in uuid:
            if uuid[key] not in canuse_tags:
                # Add permissions for each tag.

                print(str(key), str(uuid[key]))
                create_permission(name=key, tag_name=key, uuid=uuid[key], perm_string="CanUse", perm_type="Tag",
                                  subject_type="AllUsers")

    print()


@config.command(help="Change the Base URL for Navi")
@click.argument('new_url')
def url(new_url):
    database = r"navi.db"
    conn = new_db_connection(database)
    drop_tables(conn, 'url')
    create_url_table = """CREATE TABLE IF NOT EXISTS url (name text, url text);"""
    create_table(conn, create_url_table)

    info = ("Custom URL", new_url)
    with conn:
        sql = '''INSERT or IGNORE into url (name, url) VALUES(?,?)'''
        cur = conn.cursor()
        cur.execute(sql, info)


@config.command(help="Populate Navi DB with EPSS data")
@click.option('--day', '--d', default='', help="Day of the Month; EX: 01 NOT 1")
@click.option('--month', '--m', default='', help="Month of the year;EX: 04 NOT 4")
@click.option('--year', '--y', default='', help="Year of your desire;EX: 2023 NOT 23")
@click.option('--filename', default=None, help="Supply the EPSS data manually providing a CSV")
def epss(day, month, year, filename):
    if day and month and year:
        update_navi_with_epss(day, month, year, filename)
    else:
        grab_epss_today(filename)


@config.group(help="Update the local Navi DB, Change Base URL, and update EPSS")
def update():
    pass


@update.command(help="Perform a full update (30d Vulns / 90d Assets); Delete the current Database")
@click.option('--threads', default=10,
              help="Control the threads to speed up or slow down downloads - (1-20)")
@click.option('--days', default=None, help="Limit the download to X # of days")
@click.option('--c', default=None, help="Isolate your update to a tag using the provided category")
@click.option('--v', default=None, help="Isolate your update to a tag using the provided value")
@click.option('--state', multiple=True, default=["open", "reopened"],
              type=click.Choice(['open', 'reopened', 'fixed']),
              help='Isolate your update to a particular finding state')
@click.option('--severity', multiple=True, default=["critical", "high", "medium", "low", "info"],
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help='Isolate your update to a particular finding severity')
def full(threads, days, c, v, state, severity):
    if threads:
        threads_check(threads)

    exid = '0'

    if days is None:
        vuln_export(30, exid, threads, c, v, list(state), list(severity),
                    operator="gte", vpr_score=None, plugins=None)
        asset_export(90, exid, threads, c, v)
    else:
        vuln_export(days, exid, threads, c, v, list(state), list(severity),
                    operator="gte", vpr_score=None, plugins=None)
        asset_export(days, exid, threads, c, v)


@update.command(help="Update the Asset Table")
@click.option('--days', default='90', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10,
              help="Control the threads to speed up or slow down downloads - (1-20)")
@click.option('--c', default=None, help="Isolate your update by a tag using the provided category")
@click.option('--v', default=None, help="Isolate your update by a tag using the provided value")
def assets(threads, days, exid, c, v):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    asset_export(days, exid, threads, c, v)


@update.command(help="Create and Update the Agent table for more advanced Agent use-cases")
def agents():
    click.echo("\n\nGrabbing Agent data and stuffing it into the database in a table called agents. "
               "This can take some time; 5000 agents at a time.\n\n")
    download_agent_data()


@update.command(help="Update the vulns Table")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10,
              help="Control the threads to speed up or slow down downloads - (1-20)")
@click.option('--c', default=None, help="Isolate your update by a tag using the provided category")
@click.option('--v', default=None, help="Isolate your update by a tag using the provided value")
@click.option('--state', multiple=True, default=["open", "reopened"],
              type=click.Choice(['open', 'reopened', 'fixed']),
              help='Isolate your update to a particular finding state')
@click.option('--severity', multiple=True, default=["critical", "high", "medium", "low", "info"],
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help='Isolate your update to a particular finding state')
@click.option('--vpr_score', default=None, help="Isolate your Vuln data to a VPR score")
@click.option('--operator', multiple=False, default="gte", type=click.Choice(["gte", "gt", "lt" "lte"]),
              help="VPR operator")
@click.option("--plugin_id", multiple=True, type=click.INT, default=None,
              help="Plugin ID(s) that you want downloaded. Use multiple values for multiple plugins")
def vulns(threads, days, exid, c, v, state, severity, vpr_score, operator, plugin_id):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    vuln_export(days, exid, threads, c, v, list(state), list(severity), vpr_score, operator, list(plugin_id))


@update.command(help="Update the Compliance data")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10,
              help="Control the threads to speed up or slow down downloads - (1-20)")
def compliance(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    compliance_export(days, exid, threads)


@update.command(help="Update Navi DB with Fixed data for SLA processing")
@click.option('--c', default='', help="Tag Category name")
@click.option('--v', default='', help="Tag Value")
@click.option('--days', default='30', help="Limit the download to X # of days")
def fixed(c, v, days):
    fixed_export(c, v, days)


@update.command(help="Update the Navi DB with WAS data")
@click.option('--days', default='30', help="Limit the data downloaded a number of days")
def was(days):
    grab_scans(days)


@config.command(help="Parse the 3 software plugins and stuff the software into a table called software")
def software():
    update_software()


@config.command(help="Create or delete exclusions")
@click.option('--name', default=None, required=True, help="The name of your exclusion")
@click.option('--members', default=None, help="The members of your exclusion, IPs or subnets")
@click.option('--start', default=None, required=True,
              help="The start time of the exclusion - YYYY-MM-DD HH:MM")
@click.option('--end', default=None, required=True,
              help="The end time of the exclusion - YYYY-MM-DD HH:MM")
@click.option('--freq', multiple=False, required=True, default=["DAILY"],
              type=click.Choice(["ONETIME", "DAILY", "WEEKLY", "MONTHLY", "YEARLY"]),
              help='The frequency of the exclusion')
@click.option('--day')
@click.option('--c', default=None, help='Category of the Tag you want to exclude')
@click.option('--v', default=None, help='Value of the Tag you want to exclude')
def exclude(name, members, start, end, freq, day, c, v):
    try:
        if c:
            if v is None:
                click.echo("You must enter a Value if you are going to Exclude by tag.")
            if v:
                data = db_query("select asset_ip from tags where "
                                "tag_key ='" + str(c) + "' and tag_value = '" + str(v) + "';")
                members_list = []
                for asset in data:
                    members_list.append(asset[0])

                exclude_request = tio.exclusions.create(name=name,
                                                        start_time=datetime.datetime.strptime
                                                        (start, '%Y-%m-%d %H:%M'),
                                                        end_time=datetime.datetime.strptime
                                                        (end, '%Y-%m-%d %H:%M'),
                                                        frequency=freq,
                                                        members=members_list,
                                                        day_of_month=day,
                                                        description="Created using Navi; "
                                                                    "IPs by Tag: {}:{}".format(c, v))

                click.echo(exclude_request)
        else:
            if members is None:
                click.echo("\nYou need to specify a Tag or a IP/subnet to exclude\n")
                exit()
            else:
                exclude_request = tio.exclusions.create(name=name,
                                                        start_time=datetime.datetime.strptime
                                                        (start, '%Y-%m-%d %H:%M'),
                                                        end_time=datetime.datetime.strptime
                                                        (end, '%Y-%m-%d %H:%M'),
                                                        frequency=freq, members=list(members.split(",")),
                                                        day_of_month=day,
                                                        description="Created using Navi: manually entered via the CLI")
                click.echo(exclude_request)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@agent.command(help="Create a new Agent Group")
@click.option("--name", default=None, required=True,
              help="The name of the new Agent Group you want to create")
@click.option("--scanner", default=1, help="Add Agent Group to a specific scanner")
def create(name, scanner):
    try:
        group_creation = tio.agent_groups.create(name=name, scanner_id=scanner)

        click.echo("\nYour agent group: {} has been created.\n\nHere is the ID: {} and UUID : {}"
                   "\n".format(group_creation['name'], str(group_creation['id']), str(group_creation['uuid'])))
    except AttributeError:
        click.echo("Check your API Keys")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@agent.command(help="Add an agent to a Group")
@click.option("--aid", default=None, required=True, help="The agent ID of the agent you want to add ")
@click.option("--gid", default=None, required=True, help="The Group ID you want to add the agent(s) to.")
@click.option("--file", default=None, required=False, help="CSV with UUIDs as the first column.")
def add(aid, gid, file):
    try:
        if file:
            # ignore AID and use the file instead
            for agent_info in tio.agents.list():
                print(agent_info['uuid'], agent_info['id'])

            import csv
            with open(file, 'r', newline='') as new_file:
                agent_list = []
                add_agents = csv.reader(new_file)

                for rows in add_agents:
                    # UUID will be in the first column
                    agent_list.append(rows[0])

                for agent_info in tio.agents.list():
                    agent_uuid = agent_info['uuid']
                    agent_id = agent_info['id']
                    if agent_uuid in agent_list:
                        # Add agents to the Group
                        tio.agent_groups.add_agent(gid, agent_id)
        else:
            # Add agent to Group
            tio.agent_groups.add_agent(gid, aid)

            click.echo("\nYour agent has been added to the Group ID: {}\n".format(gid))
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@agent.command(help="Remove an Agent from a Agent Group")
@click.option("--aid", default=None, required=True, help="The agent ID of the agent you want to remove ")
@click.option("--gid", default=None, required=True, help="The Group ID you want to add the agent(s) to.")
def remove(aid, gid):
    try:
        # Remove an agent from a Group
        tio.agent_groups.delete_agent(gid, aid)

        click.echo("\nYour agent has been removed from the Group ID: {}\n".format(gid))
    except AttributeError:
        click.echo("Check your API Keys")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@agent.command(help="Unlink an by Agent ID")
@click.option("--aid", default=None, required=True, help="The Agent ID of the agent you want to unlink")
def unlink(aid):
    try:
        tio.agents.unlink(aid)
        click.echo("\nYour Agent: {} has been unlinked".format(aid))
    except AttributeError:
        click.echo("Check your API Keys")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@agent.command(help="Create a Agent group based on a Tag")
@click.option('--c', default=None, help="Tag Category")
@click.option('--v', default=None, help="Tag Value")
@click.option('--agent_group', default=None, help="New Agent group name")
@click.option("--scanner", default=1, help="Add Agent Group to a specific scanner")
def bytag(c, v, agent_group, scanner):
    try:
        from uuid import UUID
        data = db_query("select uuid from assets LEFT JOIN tags ON uuid == asset_uuid "
                        "where tag_key =='" + str(c) + "' and tag_value == '" + str(v) + "';")
        temp_agents = []

        # Grab a current Group ID
        group_id_test, group_uuid_test = get_group_id(agent_group)
        # If None is returned create a new Group and set the group id
        if group_id_test is None:
            click.echo("\nGroup wasn't found, creating new group\n")
            group_creation = tio.agent_groups.create(name=agent_group, scanner_id=scanner)
            group_id = group_creation['id']
        else:
            group_id = group_id_test
            click.echo("\nGroup was found! Group ID is:" + str(group_id))

        for asset in data:
            asset_uuid = asset[0]
            temp_agents.append(asset_uuid)

        click.echo("\nRetrieving agents from T.VM and comparing it to the navi database."
                   "\nMake sure you have updated recently in case nothing get's moved\n")
        for agent_info in tio.agents.list():

            # Convert agent UUID to hex to look up in db
            agent_uuid = UUID(agent_info['uuid']).hex
            agent_id = agent_info['id']
            tag_uuid = db_query("select uuid from assets where agent_uuid='{}'".format(agent_uuid))
            if tag_uuid[0][0] in temp_agents:
                tio.agent_groups.add_agent(group_id, agent_id)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@config.command(help="Parse plugin 10863(certificate information) into it's own table in the database")
def certificates():
    update_certificates()


@update.command(help="Update Everything:Assets, Vulns, Audits, Agents, Fixed, EPSS, WAS, Software and Certs")
@click.option('--threads', default=10,
              help="Control the threads to speed up or slow down downloads - (1-20)")
@click.option('--days', default=30, help="Limit the download to X # of days")
@click.option('--c', default=None, help="Isolate your update to a tag using the provided category")
@click.option('--v', default=None, help="Isolate your update to a tag using the provided value")
@click.option('--state', multiple=True, default=["open", "reopened"],
              type=click.Choice(['open', 'reopened', 'fixed']),
              help='Isolate your update to a particular finding state')
@click.option('--severity', multiple=True, default=["critical", "high", "medium", "low", "info"],
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help='Isolate your update to a particular finding severity')
@click.option("-apps", is_flag=True, help="Avoid updating the WAS tables")
@click.option("-audits", is_flag=True, help="Avoid updating the compliance table")
@click.option("-fixes", is_flag=True, help="Avoid updating the fixed table")
def everything(threads, days, c, v, state, severity, apps, audits, fixes):
    import time
    start = time.time()
    click.echo("*" * 70)
    click.echo("    Updating the Vulns and Plugins Tables from the vulns export API")
    click.echo("-" * 70)
    vuln_export(30, "0", threads, c, v, list(state), list(severity),
                operator="gte", vpr_score=None, plugins=None)
    group_by_plugins()

    click.echo("*" * 70)
    click.echo("    Updating the Assets and Tags Tables from the asset export API")
    click.echo("-" * 70)
    asset_export(90, "0", threads, c, v)

    if not audits:
        click.echo("*" * 70)
        click.echo("    Updating the Compliance Table from the Compliance export API")
        click.echo("-" * 70)
        compliance_export(days, "0", threads)

    if not apps:
        click.echo("*" * 70)
        click.echo("Updating the Was data from the WAS SCAN endpoints(soon to be exports)")
        click.echo("-" * 70)
        grab_scans(days)

    if not fixes:
        click.echo("*" * 70)
        click.echo("Updating the Fixed Table with Fixed vulns from the vulns export API")
        click.echo("-" * 70)
        fixed_export(c, v, days)

    click.echo("*" * 70)
    click.echo("Updating the Cert Table with Certificate Information parsed from plugin 10863")
    click.echo("-" * 70)
    update_certificates()

    click.echo("*" * 70)
    click.echo("Updating the Software table by parsing plugins - 22869(linux),20811(Windows),83991(Mac)")
    click.echo("-" * 70)
    update_software()

    click.echo("*" * 70)
    click.echo("   Updating the Agent table with agent data from the Agent API endpoint")
    click.echo("-" * 70)
    download_agent_data()

    click.echo("*" * 70)
    click.echo("Updating the EPSS table with EPSS data from EPSS downloadble CSV")
    click.echo("-" * 70)
    grab_epss_today(None)

    click.echo("*" * 70)
    click.echo("Parsing Paths out of each Plugin and creating a Table called vuln_paths")
    click.echo("-" * 70)
    search_for_path()

    click.echo("*" * 70)
    click.echo("Grouping vulnerabilities together by Application Name in a table called Vuln_routes")
    click.echo("-" * 70)
    group_by_plugins()

    end = time.time()
    click.echo("\nNow that we are done, let's check all of the tables.")
    click.echo("-" * 52)
    click.echo("-" * 52)
    grab_data_info()
    click.echo("*" * 60)
    click.echo("This is how long it took: {} Seconds".format(str(end - start)))
    click.echo("-" * 60)
    click.echo("\n\n")


@update.command(help="Create a zipper table for merging EPSS data with Plugins")
def zipper():
    zipper_epss_plugin()


@update.command(help="Group Plugins by Application/Operating system for routing vulns")
def route():
    group_by_plugins()


@update.command(help="Divide routes by Paths found in the plugin output")
def paths():
    search_for_path()
