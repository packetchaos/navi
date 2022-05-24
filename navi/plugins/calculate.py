import click
from .fixed_export import calculate_sla


@click.command(help="Calculate SLA times")
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
