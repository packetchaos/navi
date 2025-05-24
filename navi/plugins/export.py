import click
import csv
import textwrap
from .database import db_query
from .query_export import query_export
from .agent_group_export import agent_group_export
from .user_export import user_export
from .compliance_export_csv import compliance_export_csv
from .query_export_32K import export_query
from .api_wrapper import request_xml
from .agent_to_db import download_agent_data


@click.group(help="Export tenable VM Data")
def export():
    pass


@export.command(help="Export All Asset data in the Navi Database to a CSV")
@click.option('--file', default="asset_data", help="Name of the file excluding 'csv'")
def assets(file):
    click.echo("\nExporting your data now. Saving {}.csv now...\n".format(file))
    asset_query = "select * from assets;"
    query_export(asset_query, file)


@export.command(help="Export All Agent data into a CSV")
@click.option('--filename', default="agent_data", help="Name of the file excluding 'csv'")
def agents(filename):
    download_agent_data()
    click.echo("\nExporting your data now. Saving {}.csv now...\n".format(filename))
    agent_query = "select * from agents;"
    query_export(agent_query, filename)


@export.command(help="Export Licensed Assets into a CSV")
@click.option('--file', default="licensed_data", help="Name of the file excluding 'csv'")
def licensed(file):
    click.echo("\nExporting your data now. Saving {}.csv now...\n".format(file))
    licensed_query = ("SELECT ip_address, fqdn, uuid, last_licensed_scan_date "
                      "from assets where last_licensed_scan_date != ' ';")
    query_export(licensed_query, file)


@export.command(help="Export All assets of a given network")
@click.argument('network_uuid')
@click.option('--file', default="network_data", help="Name of the file excluding 'csv'")
def network(network_uuid, file):
    click.echo("\nExporting your data now. Saving {}.csv now...".format(file))
    network_query = "SELECT * from assets where network=='{}';".format(network_uuid)
    query_export(network_query, file)


@export.command(help='Export assets by query to the vuln db')
@click.argument('statement')
@click.option('--file', default="query_data", help="Name of the file excluding 'csv'")
@click.option('-fix', is_flag=True, help="Fix for Vuln Outputs with over 32K chars")
def query(statement, file, fix):
    if fix:
        export_query(statement, file)
    else:
        query_export(statement, file)


@export.command(help='Export Agents by Group name')
@click.argument('group_name')
def group(group_name):
    click.echo("\nExporting your data now.  Saving agent_group_data.csv now...")
    agent_group_export(group_name)


@export.command(help="Export All assets by tag; Include ACR and AES into a CSV")
@click.option('--c', default=None, required=True, help="Export bytag with the following Category name")
@click.option('--v', default=None, required=True, help="Export bytag with the Tag Value; "
                                                       "requires --c and Category Name")
@click.option('--file', default="bytag", help="Name of the file excluding 'csv'")
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low', 'info'],
                                              case_sensitive=False), multiple=True)
def bytag(c, v, file, severity):

    if severity:
        # If Severity is chosen then we will export vuln details
        if len(severity) == 1:
            # multiple choice values are returned as a tuple.
            # Here I break it out and put it in the format needed for sql
            asset_query = ("select vulns.*, tags.asset_uuid from vulns left join tags on "
                           "vulns.asset_uuid = tags.asset_uuid where vulns.severity in ('{}');").format(severity[0])
            query_export(asset_query, file)
        else:

            asset_query = ("select vulns.*, tags.asset_uuid from vulns left join tags on "
                           "vulns.asset_uuid = tags.asset_uuid where vulns.severity in {};").format(severity)
            query_export(asset_query, file)
    else:
        tag_assets = ("SELECT assets.*, tags.asset_uuid from assets left join tags on assets.uuid = tags.asset_uuid "
                      "and tags.tag_key='") + c + "' and tags.tag_value='" + v + "';"

        query_export(tag_assets, file)


@export.command(help="Export User and Role information into a CSV")
def users():
    click.echo("\nExporting User Data now. Saving user-summary.csv now...\n")
    user_export()


@export.command(help="Export Compliance information into a CSV")
@click.option('--name', default=None, help="Exact name of the Audit file to be exported.  Use 'navi display audits' to "
                                           "get the right name")
@click.option('--uuid', default=None, help="UUID of the Asset for your export")
@click.option('--file', default="compliance_data.csv", help="Name of the file excluding '.csv'")
def compliance(name, uuid, file):
    click.echo("\nExporting your requested Compliance data into a CSV\n")
    compliance_export_csv(name, uuid, file)


@export.command(help="Export All Vulnerability data in the Navi Database to a CSV")
@click.option('--file', default="vuln_data", help="Name of the file excluding '.csv'")
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low', 'info'],
                                              case_sensitive=False), multiple=True)
def vulns(file, severity):
    click.echo("\nExporting your data now. Saving {}.csv now...\n".format(file))

    if severity:

        if len(severity) == 1:
            # multiple choice values are returned as a tuple.
            # Here I break it out and put it in the format needed for sql
            asset_query = "select * from vulns where severity in ('{}');".format(severity[0])
        else:
            # Here I just send the tuple in the query
            asset_query = "select * from vulns where severity in {};".format(severity)
    else:
        asset_query = "select * from vulns;"

    query_export(asset_query, file)


@export.command(help="Export Vulnerabilities that have failed")
def failures():
    click.echo("\nExporting ALl vulnerabilities that failed your SLA\n This requires you run 'navi update fixed'")
    query_export("select * from fixed where pass_fail=='Fail' and state !='FIXED';", "sla_backlog")


@export.command(help="Export parsed plugins")
@click.option('-user_names', is_flag=True, help="Export Users by parsing the 45478 plugin")
@click.option('--name', default='parsed_plugin_data')
def parsed(name, user_names):
    with open('{}.csv'.format(name), mode='w', encoding='utf-8', newline="") as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
        header = ['Asset_UUID', "User Found"]
        agent_writer.writerow(header)

        if user_names:
            raw_data = db_query("select asset_uuid, output from vulns where plugin_id='45478'")

            # pprint.pprint(eval(str(raw_data))[1][1])
            plugin_data = eval(str(raw_data))

            for asset in plugin_data:
                # remove the +users in the beginning of the string
                output_data = asset[1][18:]

                # Split the users at "|"
                output_data_split = str(output_data).split("|")

                for user in output_data_split:
                    user_list = []
                    strip_output = str(user).strip()

                    if "Computer" not in strip_output:
                        split_output = strip_output.split(",")[0][3:]

                        if asset[0]:
                            user_list.append(asset[0])
                            user_list.append(str(split_output))

                            agent_writer.writerow(user_list)


@export.command(help="Export policies for a migration")
@click.option('--pid', default=None, help="Policy ID to be exported. Use 'navi display policies' for IDs")
def policy(pid):
    def write_file(blob):
        with open("{}.nessus".format(pid), 'w') as file:
            file.write(blob)
    policy_data = request_xml('GET', '/policies/{}/export'.format(pid))
    write_file(str(policy_data))


@export.command(help="Pull out asset CVE data from each plugin into a nice CSV for CVE to CVE comparison")
@click.argument('uuid')
def compare(uuid):
    data = db_query("select plugin_id, plugin_name, cvss_base_score, cvss3_base_score, cves, severity, score, "
                    "first_found, last_found from vulns where asset_uuid='{}' and cves !=' ';".format(uuid))

    with open('cve_data_{}.csv'.format(uuid), mode='w', encoding='utf-8', newline="") as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        header_list = ["Plugin ID", "Plugin Name", "CVE", "CVSS", "CVSS3", "VPR Score", "EPSS Score", "Severity",
                       "First Found", "Last_Found", "Instances"]

        agent_writer.writerow(header_list)

        master_list = []
        click.echo("\n{:10} {:75} {:16} {:6} {:6} {:6} {:7} {:10} {}".format("Plugin ID", "Plugin Name", "CVE",
                                                                             "CVSS", "CVSS3", "VPR", "EPSS", "Severity",
                                                                             "instances"))
        click.echo("-" * 150)
        for plugin in data:
            plugin_id = plugin[0]
            plugin_name = str(plugin[1])
            cvss = str(plugin[2])
            cvss3 = str(plugin[3])

            try:
                cve_list = eval(plugin[4])
            except SyntaxError:
                cve_list = ["NO-CVE"]

            severity = plugin[5]
            vpr = str(plugin[6])
            first_found = str(plugin[7])
            last_found = str(plugin[8])

            for cve in cve_list:
                epss_data = 'N/A'
                if cve not in master_list:
                    # Count total instances
                    instances = db_query("select count(*) from vulns where cves LIKE '%" + cve + "%';")

                    master_list.append(cve)
                    try:
                        epss_data_raw = db_query("select epss_value from epss where cve='{}'".format(cve))
                        epss_data = str(epss_data_raw[0][0])
                    except IndexError:
                        pass
                    click.echo("{:10} {:75} {:16} {:6} {:6} {:6} {:7} {:10} {}".format(plugin_id,
                                                                                       textwrap.shorten(plugin_name,
                                                                                                        width=65), cve,
                                                                                       cvss, cvss3, vpr, epss_data,
                                                                                       severity, instances[0][0]))

                    csv_update_list = [plugin_id, plugin_name, cve, cvss, cvss3, vpr, epss_data, severity,
                                       first_found, last_found, instances[0][0]]
                    agent_writer.writerow(csv_update_list)

    click.echo("\nYou're export: cve_compare_{}.csv is finished\n".format(uuid))
