import click
from .plugins import plugin_loader


@click.group(help="This tool is not Supported by Tenable. \n Issues? Please submit an issue on Github.")
@click.pass_context
def cli(ctx):
    pass


plugin_loader(cli)
