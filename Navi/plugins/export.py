import click
from .licensed_export import licensed_export
from .agent_export import agent_export
from .webapp_export import webapp_export
from .consec_export import consec_export
from .csv_export import csv_export
from .lumin_export import lumin_export

@click.command(help="Export data into a CSV")
@click.option('-assets', is_flag=True, help='Exports all Asset data into a CSV')
@click.option('-agents', is_flag=True, help="Export all Agent data into a CSV")
@click.option('-webapp', is_flag=True, help="Export Webapp Scan Summary into a CSV")
@click.option('-consec', is_flag=True, help="Export Container Security Summary into a CSV")
@click.option('-licensed', is_flag=True, help="Export a List of all the Licensed Assets")
@click.option('-lumin', is_flag=True, help="Export all Asset data including ACR and AES into a CSV. This will take some time")
def export(assets, agents, webapp, consec, licensed, lumin):
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
        print("Saving agent_lumin.csv now...\n")
        lumin_export()
