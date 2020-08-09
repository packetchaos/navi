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


@click.command(help="Export data into a CSV")
@click.option('-assets', is_flag=True, help='Exports all Asset data into a CSV')
@click.option('-agents', is_flag=True, help="Export all Agent data into a CSV")
@click.option('-was', is_flag=True, help="Export Webapp Scan Summary into a CSV - WAS V2")
@click.option('-consec', is_flag=True, help="Export Container Security Summary into a CSV")
@click.option('-licensed', is_flag=True, help="Export a List of all the Licensed Assets")
@click.option('-lumin', is_flag=True, help="Export all Asset data including ACR and AES into a CSV. This will take some time")
@click.option('--network', default='', help="Export All assets of a given network")
@click.option('--query', default='', help="Export assets by query to the vuln db")
@click.option('--group', default='', help="Export Agents by Group name - API limits 5000 Agents")
@click.option('-bytag', is_flag=True, help="Export all assets by tag; Include ACR and AES into a CSV")
@click.option('--c', default='', help="Export bytag with the following Category name")
@click.option('--v', default='', help="Export bytag with the Tag Value; requires --c and Category Name")
@click.option('--ec', default='', help="Exclude tag from export with Tag Category; requires --ev")
@click.option('--ev', default='', help="Exclude tag from export with Tag Value; requires --ec")
def export(assets, agents, consec, licensed, lumin, network, query, group, bytag, c, v, ec, ev, was):
    if assets:
        print("\nExporting your data now. Saving asset_data.csv now...\n")
        csv_export()

    if agents:
        print("\nExporting your data now. Saving agent_data.csv now...\n")
        agent_export()

    if consec:
        print("\nExporting your data now. Saving consec_data.csv now...\n")
        consec_export()

    if licensed:
        print("\nExporting your data now. Saving licensed_data.csv now...\n")
        licensed_export()

    if lumin:
        print("\nExporting your data now. This could take some time.  300 Assets per minute max.")
        print("Saving asset_lumin.csv now...\n")
        lumin_export()

    if network:
        print("\nExporting your data now. Saving network_data.csv now...")
        network_export(network)

    if query != '':
        query_export(query)

    if group != '':
        print("\nExporting your data now.  Saving agent_group_data.csv now...")
        agent_group_export(group)

    if bytag:
        if c == '':
            print("Tag Category is required.  Please use the --c command")
            exit()

        if v == '':
            print("Tag Value is required. Please use the --v command")
            exit()

        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            try:
                new_list = []
                cur = conn.cursor()
                cur.execute("SELECT asset_uuid, asset_ip from tags where tag_key='" + c + "' and tag_value='" + v + "';")

                assets = cur.fetchall()

                for asset in assets:
                    # This will need to change to UUID once the API gets fixed for Lumin; right not it is by IP
                    # for Each IP check to see if it exists in the exclude tag pair.  If it doesn't add it to the list.
                    check_for_no = tag_checker(asset[1], ec, ev)
                    if check_for_no == 'no':
                        new_list.append(asset[0])
            except conn.OperationalError:
                print('Sorry Right now, navi doesn\'t support \' in a tag')

        tag_export(new_list)

    if was:
        print("\nExporting your data now. Saving was_v2_data.csv now...")
        was_export()
