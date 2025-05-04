import click
from .plugins import plugin_loader


@click.group(help="This tool is supported through Github and not by Tenable support.\n"
                  "Please include as much information as possible when submitting an issue on github\n\n"
                  "Two commands are Required to make navi work properly\n\n"
                  "navi config keys - which requires TVM API keys for authentication\n"
                  "\nnavi config update full - to update the vulns table and the assets table\n")
@click.pass_context
def cli(ctx):
    pass


plugin_loader(cli)
