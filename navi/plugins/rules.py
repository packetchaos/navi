import click
from os import system as sys
from .database import db_query
import pprint


@click.group(help="Run Navi Tag Rules")
def rules():
    pass


@rules.command()
def run():
    try:
        rule_data = db_query("select * from rules;")

        pprint.pprint(rule_data)

        for rule in rule_data:
            if rule[3] == 'plugin_id':

                print("navi tag --c \"{}\" --v \"{}\" --plugin {}".format(rule[1], rule[2], rule[4]))
                sys("navi tag --c \"{}\" --v \"{}\" --plugin {}".format(rule[1], rule[2], rule[4]))
            elif rule[3] == 'plugin_name':
                print("navi tag --c \"{}\" --v \"{}\" --name \"{}\"".format(rule[1], rule[2], rule[4]))
                sys("navi tag --c \"{}\" --v \"{}\" --name \"{}\"".format(rule[1], rule[2], rule[4]))
            elif rule[3] == 'plugin_output':
                print("navi tag --c \"{}\" --v \"{}\" --plugin {} --output {}".format(rule[1], rule[2], rule[5], rule[4]))
                sys("navi tag --c \"{}\" --v \"{}\" --plugin {} --output {}".format(rule[1], rule[2], rule[5], rule[4]))
            elif rule[3] == 'cve':
                print("navi tag --c \"{}\" --v \"{}\" --cve {}".format(rule[1], rule[2], rule[4]))
                sys("navi tag --c \"{}\" --v \"{}\" --cve {}".format(rule[1], rule[2], rule[4]))
            elif rule[3] == 'xref':
                print("navi tag --c \"{}\" --v \"{}\" --xref {}".format(rule[1], rule[2], rule[4]))
                sys("navi tag --c \"{}\" --v \"{}\" --xref {}".format(rule[1], rule[2], rule[4]))
    except:
        click.echo("\nYou don't have any Rules")
