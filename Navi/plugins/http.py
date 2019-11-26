import click
import os

@click.command(help="Spin up a http server to extract data from the container")
def http():
    try:
        os.system("python3 -m http.server")
    except:
        print("This feature is for container's only")
