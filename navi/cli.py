import click
from .plugins import plugin_loader


@click.group()
@click.pass_context
def cli(ctx):
    click.echo("Hey Listen!")


plugin_loader(cli)
