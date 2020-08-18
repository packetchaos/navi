import click


def error_msg(msg):
    click.echo("Check your API keys or your internet connection")
    click.echo("I received the following Error: \n ")
    click.echo(msg)
