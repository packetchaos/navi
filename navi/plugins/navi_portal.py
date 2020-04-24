import click
import os


@click.command(help="A web interfae to explore the Navi DB")
def portal():
    try:
        os.system("python3 portal.py")
    except:
        print("oops")
