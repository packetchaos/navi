import click
from .licensed_export import licensed_export
from .agent_export import agent_export
from .consec_export import consec_export
from .csv_export import csv_export
from .lumin_export import lumin_export
from .database import new_db_connection
from .tag_export import tag_export
from .tag_helper import tag_checker
from .network_export import network_export
from .query_export import query_export
from .was_v2_export import was_export
from .agent_group_export import agent_group_export
from .lumin_quick_export import lumin_quick_export
from .user_export import user_export
from .compliance_export_csv import compliance_export_csv


@click.group(help="Export Tenable.io Data")
def export():
    pass


@export.command(help="Export All Asset data in the Navi Database to a CSV")
def assets():
    click.echo("\nExporting your data now. Saving asset_data.csv now...\n")
    csv_export()


@export.command(help="Export All Agent data into a CSV")
def agents():
    click.echo("\nExporting your data now. Saving agent_data.csv now...\n")
    agent_export()


@export.command(help="Export Container Security Summary into a CSV")
def consec():
    click.echo("\nExporting your data now. Saving consec_data.csv now...\n")
    consec_export()


@export.command(help="Export Licensed Assets into a CSV")
def licensed():
    click.echo("\nExporting your data now. Saving licensed_data.csv now...\n")
    licensed_export()


@export.command(help="Export all Asset data including ACR and AES into a CSV")
@click.option("-v", is_flag=True, help="Include ACR Drivers.  This will make a call per asset!")
def lumin(v):

    if v:
        click.echo("\nExporting your data now. This could take some time.  300 Assets per minute max.")
        click.echo("Saving asset_lumin.csv now...\n")
        lumin_export()
    else:
        click.echo("\nExporting your data now.")
        click.echo("Saving asset_lumin.csv now...\n")
        lumin_quick_export()


@export.command(help="Export All assets of a given network")
@click.argument('network_uuid')
def network(network_uuid):
    click.echo("\nExporting your data now. Saving network_data.csv now...")
    network_export(network_uuid)


@export.command(help='Export assets by query to the vuln db')
@click.argument('statement')
def query(statement):
    query_export(statement)


@export.command(help='Export Agents by Group name - API limits 5000 Agents')
@click.argument('group_name')
def group(group_name):
    click.echo("\nExporting your data now.  Saving agent_group_data.csv now...")
    agent_group_export(group_name)


@export.command(help="Export all assets by tag; Include ACR and AES into a CSV")
@click.option('--c', default='', help="Export bytag with the following Category name")
@click.option('--v', default='', help="Export bytag with the Tag Value; requires --c and Category Name")
@click.option('--ec', default='', help="Exclude tag from export with Tag Category; requires --ev")
@click.option('--ev', default='', help="Exclude tag from export with Tag Value; requires --ec")
def bytag(c, v, ec, ev):
    if c == '':
        click.echo("Tag Category is required.  Please use the --c command")
        exit()

    if v == '':
        click.echo("Tag Value is required. Please use the --v command")
        exit()

    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        try:
            new_list = []
            cur = conn.cursor()
            cur.execute("SELECT asset_uuid, asset_ip from tags where tag_key='" + c + "' and tag_value='" + v + "';")

            tag_assets = cur.fetchall()

            for asset in tag_assets:
                # This will need to change to UUID once the API gets fixed for Lumin; right not it is by IP
                # for Each IP check to see if it exists in the exclude tag pair.  If it doesn't add it to the list.
                check_for_no = tag_checker(asset[1], ec, ev)
                if check_for_no == 'no':
                    new_list.append(asset[0])
        except conn.OperationalError:
            click.echo('Sorry Right now, navi doesn\'t support \' in a tag')

    tag_export(new_list)


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
