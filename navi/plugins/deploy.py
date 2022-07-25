import click
import os


@click.command(help="Deploy Navi Tag Center using a Docker container: navigate to http://localhost:5000")
def deploy():
    if click.confirm('This command downloads the silentninja/navi-ent docker container and runs it on port 5000 using the current navi database. Deploy?'):
        try:
            os.system("docker run -d -p 5000:5000 --mount type=bind,source=\"$(pwd)\",target=/usr/src/app/data silentninja/navi-ent")
        except os.error:
            click.echo("You might not have Docker installed")
