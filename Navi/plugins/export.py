import click
from .licensed_export import licensed_export
from .agent_export import agent_export
from .webapp_export import webapp_export
from .consec_export import consec_export
from .csv_export import csv_export
from .lumin_export import lumin_export
from .database import new_db_connection
from .tag_export import tag_export

@click.command(help="Export data into a CSV")
@click.option('-assets', is_flag=True, help='Exports all Asset data into a CSV')
@click.option('-agents', is_flag=True, help="Export all Agent data into a CSV")
@click.option('-webapp', is_flag=True, help="Export Webapp Scan Summary into a CSV")
@click.option('-consec', is_flag=True, help="Export Container Security Summary into a CSV")
@click.option('-licensed', is_flag=True, help="Export a List of all the Licensed Assets")
@click.option('-lumin', is_flag=True, help="Export all Asset data including ACR and AES into a CSV. This will take some time")
@click.option('-bytag', is_flag=True, help="Export all assets by tag; Include ACR and AES into a CSV")
@click.option('--c', default='', help="Export bytag with the following Category name")
@click.option('--v', default='', help="Export bytag with the Tag Value; requires --c and Category Name")
def export(assets, agents, webapp, consec, licensed, lumin, bytag, c, v):
    if assets:
        print("\nExporting your data now. Saving asset_data.csv now...\n")
        csv_export()

    if agents:
        print("\nExporting your data now. Saving agent_data.csv now...\n")
        agent_export()

    if webapp:
        print("\nExporting your data now. Saving webapp_data.csv now...\n")
        webapp_export()

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

    if bytag:
        if c == '':
            print("Category is required.  Please use the --c command")

        if v == '':
            print("Value is required. Please use the --v command")

        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            new_list = []
            cur = conn.cursor()
            cur.execute("SELECT asset_uuid from tags where tag_key='" + c + "' and tag_value='" + v + "';")

            assets = cur.fetchall()
            for asset in assets:
                new_list.append(asset[0])
        tag_export(new_list)
