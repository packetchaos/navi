import click
from .fixed_export import calculate_sla


@click.command(help="Calculate SLA times")
def calculate():

    calculate_sla("total")
    calculate_sla("critical")
    calculate_sla("high")
    calculate_sla("medium")
    calculate_sla("low")
    click.echo()
