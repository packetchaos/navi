import click
import os


@click.command(help="Open up a Netcat listener to accept files over port 8000")
def listen():
    try:
        print("\nI'm opening a connection so you can send a file into the container")
        print("\nuse this command on your pc to send data to the connector: nc 0.0.0.0 8000 < \"yourfile.csv\"\n")
        os.system("nc -l -p 8000 > newfile.csv")
    except os.error:
        print("This command uses netcat and is only meant for navi running in a docker container")
        print("You probably don't have netcat installed")
