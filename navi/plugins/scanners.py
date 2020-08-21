import click
from .api_wrapper import tenb_connection

tio = tenb_connection()


def nessus_scanners():
    click.echo("\n{:35s} {:20} {}".format("Scanner Name", "Scanner ID", "Scanner UUID"))
    click.echo("-" * 150)
    for scanners in tio.scanners.list():
        click.echo("{:35s} {:20} {}".format(str(scanners["name"]), str(scanners["id"]), str(scanners['uuid'])))
    click.echo()
