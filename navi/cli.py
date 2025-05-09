import click
from .plugins import plugin_loader


def general_help():
    click.echo()
    click.echo("*" * 75)
    click.echo("This tool is supported through Github and not by Tenable support.\n"
               "Please include as much information as possible when submitting an issue on github")
    click.echo("*" * 75)
    click.echo("\n           Level up your Exposure Management Game with Navi!")
    click.echo("-" * 75)
    click.echo()


@click.group(help=general_help())
@click.pass_context
def cli(ctx):
    pass


plugin_loader(cli)
