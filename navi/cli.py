import click
from .plugins import plugin_loader


def general_help():
    click.echo()
    click.echo("*" * 75)
    click.echo("This tool is supported by Songbird Systems with a support contract - support@songbirdsystems.com\n"
               "No contract? Submit a github Issue. Please include as much information as possible."
               "\nThis tool is not supported by Tenable\n")
    click.echo("*" * 75)
    click.echo("\n           Level up your Exposure Management Game with Navi!")
    click.echo("-" * 75)
    click.echo()


@click.group(help=general_help())
@click.pass_context
def cli(ctx):
    pass


plugin_loader(cli)
