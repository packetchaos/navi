import click
from .agent_export import agent_export
from .consec_export import consec_export
from .lumin_export import lumin_export
from .database import db_query
from .tag_export import tag_export
from .tag_helper import tag_checker
from .query_export import query_export
from .was_v2_export import was_export
from .agent_group_export import agent_group_export
from .user_export import user_export
from .compliance_export_csv import compliance_export_csv


@click.group(help="Export Tenable.io Data")
def export():
    pass


@export.command(help="Export All Asset data in the Navi Database to a CSV")
@click.option('--file', default="asset_data", help="Name of the file excluding 'csv'")
def assets(file):
    click.echo("\nExporting your data now. Saving {}.csv now...\n".format(file))
    asset_query = "select * from assets;"
    query_export(asset_query, file)


@export.command(help="Export All Agent data into a CSV")
def agents():
    click.echo("\nExporting your data now. Saving agent_data.csv now...\n")
    agent_export()


@export.command(help="Export Container Security Summary into a CSV")
def consec():
    click.echo("\nExporting your data now. Saving consec_data.csv now...\n")
    consec_export()


@export.command(help="Export Licensed Assets into a CSV")
@click.option('--file', default="licensed_data", help="Name of the file excluding 'csv'")
def licensed(file):
    click.echo("\nExporting your data now. Saving {}.csv now...\n".format(file))
    licensed_query = "SELECT ip_address, fqdn, uuid, last_licensed_scan_date from assets where last_licensed_scan_date != ' ';"
    query_export(licensed_query, file)


@export.command(help="Export all Asset data including ACR and AES into a CSV")
@click.option("-v", is_flag=True, help="Include ACR Drivers.  This will make a call per asset!")
@click.option('--file', default="lumin_data", help="Name of the file excluding 'csv'")
def lumin(v, file):

    if v:
        click.echo("\nExporting your data now. This could take some time.  300 Assets per minute max.")
        click.echo("Saving {}.csv now...\n".format(file))
        lumin_export()
    else:
        click.echo("\nExporting your data now.")
        click.echo("Saving {}.csv now...\n".format(file))
        asset_query = "select * from assets;"
        query_export(asset_query, file)


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
def query(statement, file):
    query_export(statement, file)


@export.command(help='Export Agents by Group name - API limits 5000 Agents')
@click.argument('group_name')
def group(group_name):
    click.echo("\nExporting your data now.  Saving agent_group_data.csv now...")
    agent_group_export(group_name)


@export.command(help="Export all assets by tag; Include ACR and AES into a CSV")
@click.option('--c', default=None, required=True, help="Export bytag with the following Category name")
@click.option('--v', default=None, required=True, help="Export bytag with the Tag Value; requires --c and Category Name")
@click.option('--ec', default=None, help="Exclude tag from export with Tag Category; requires --ev")
@click.option('--ev', default=None, help="Exclude tag from export with Tag Value; requires --ec")
@click.option('--file', default="bytag", help="Name of the file excluding 'csv'")
@click.option('-vulncounts', is_flag=True, help="Export Severity vulnerability Counts per asset. This will take some time...")
def bytag(c, v, ec, ev, file, vulncounts):
    new_list = []

    tag_assets = db_query("SELECT asset_uuid from tags where tag_key='" + c + "' and tag_value='" + v + "';")

    for asset in tag_assets:
        asset_uuid = asset[0]
        # Check the tag isn't apart of the exclude tag given
        if ev:
            check_for_no = tag_checker(asset_uuid, ec, ev)
            if check_for_no == 'no':
                new_list.append(asset_uuid)
        else:
            new_list.append(asset_uuid)

    if vulncounts:
        # Tell the export to pull verbose data - vunlcounts
        tag_export(new_list, file, 1)
    else:
        tag_export(new_list, file, 0)


@export.command(help="Export Webapp Scan Summary into a CSV - WAS V2")
def was():
    click.echo("\nExporting your data now. Saving was_summary_data.csv now...")
    was_export()


@export.command(help="Export User and Role information into a CSV")
def users():
    click.echo("\nExporting User Data now. Saving user-summary.csv now...\n")
    user_export()


@export.command(help="Export Compliance information into a CSV")
@click.option('--name', default=None, help="Exact name of the Audit file to be exported.  Use 'navi display audits' to "
                                           "get the right name")
@click.option('--uuid', default=None, help="UUID of the Asset for your export")
def compliance(name, uuid):
    click.echo("\nExporting your requested Compliance data into a CSV\n")
    compliance_export_csv(name, uuid)
