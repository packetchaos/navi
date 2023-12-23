import click
from .dbconfig import create_software_table
from .database import db_query

#This is just going to be an option to look at software, so I am not going to create this table through the dbconfig keys command.
#Going to us the begin command here to create the db table

@click.group(help="Generate a report of software in your environment")

def software():
    #print("Testing output of entire software command!")
    pass

@software.command(help="Create the database table and populate the software data")
def begin():

	click.echo("Creating the DB Table")
	create_software_table()


@software.command(help="Test printing your input out")
@click.option("--textinput", default='',required=True, help="Enter the text you want to be printed")
def print(textinput):
	click.echo("\nPreparing to Print\n")
	
	if textinput != '':
		click.echo(textinput)
		click.echo("\n")
	else:
		click.echo("The input was blank. Please enter a value to print\n")


@software.command(help="Print out what hosts had installed software found on them, across all 3 Major OS")
def oscheck():
	click.echo("Checking...")
	
	#Didn't even try this one
	#rows = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON asset_uuid = uuid where plugin_id=%s" % pid)

	#Didn't work
	#plugin(22869,"installed")

	#Might work but hasn't produced any actual output yet. 
	click.echo("Linux Hosts with installed software found")
	find_by_plugin(22869)
	click.echo("Windows Hosts with installed software found")
	find_by_plugin(20811)
	click.echo("Mac Hosts with installed software found")
	find_by_plugin(83991)






#Copied from find.py
def find_by_plugin(pid):
    rows = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON asset_uuid = uuid where plugin_id=%s" % pid)

    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    for row in rows:
        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(pid), row[0], textwrap.shorten(row[2], 46), row[1], row[3]))

    click.echo()

#Copied from find.py
def plugin(plugin_id, o):
    if not str.isdigit(plugin_id):
        click.echo("You didn't enter a number")
        exit()
    else:
        if o != "":
            click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
            click.echo("-" * 150)

            plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON "
                                   "asset_uuid = uuid where plugin_id='" + plugin_id + "' and output LIKE '%" + o + "%';")

            for row in plugin_data:
                try:
                    fqdn = row[2]
                except:
                    fqdn = " "
                click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(plugin_id), row[0], textwrap.shorten(fqdn, 46), row[1], row[3]))

        else:
            find_by_plugin(plugin_id)