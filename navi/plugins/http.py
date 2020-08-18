import click
import os


@click.command(help="Spin up a http server to extract data from the Docker container")
def http():
    try:
        os.system("python3 -m http.server")
    except os.error:
        click.echo("This feature is for Docker container's only")
