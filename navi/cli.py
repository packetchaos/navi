import click
from .plugins import plugin_loader


@click.group()
@click.pass_context
def cli(ctx):
    pass


plugin_loader(cli)
