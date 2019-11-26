import click
from .licensed_export import licensed_export
from .agent_export import agent_export
from .webapp_export import webapp_export
from .consec_export import consec_export
from .csv_export import csv_export


@click.command(help="Export data into a CSV")
@click.option('-assets', is_flag=True, help='Exports all Asset data into a CSV')
@click.option('-agents', is_flag=True, help="Export all Agent data into a CSV")
@click.option('-webapp', is_flag=True, help="Export Webapp Scan Summary into a CSV")
@click.option('-consec', is_flag=True, help="Export Container Security Summary into a CSV")
@click.option('-licensed', is_flag=True, help="Export a List of all the Licensed Assets")
def export(assets, agents, webapp, consec, licensed):
    if assets:
        print("Exporting your data now. Saving asset_data.csv now...")
        print()
        csv_export()

    if agents:
        print("Exporting your data now. Saving agent_data.csv now...")
        print()
        agent_export()

    if webapp:
        print("Exporting your data now. Saving webapp_data.csv now...")
        print()
        webapp_export()

    if consec:
        print("Exporting your data now. Saving consec_data.csv now...")
        print()
        consec_export()

    if licensed:
        print("Exporting your data now. Saving licensed_data.csv now...")
        print()
        licensed_export()
