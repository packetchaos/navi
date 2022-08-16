import click
from .api_wrapper import tenb_connection
import textwrap

tio = tenb_connection()


@click.group(help="Perform common tasks against Agents and Agent Groups")
def agent():
    pass


@agent.command(help="Display Agent information - Agent ID/UUID")
@click.option("--aid", default=None, help="Display Agent information using the Agent ID")
def display(aid):
    try:
        if aid:
            try:
                agent_details = tio.agents.details(aid)

                click.echo("\nAgent Details")
                click.echo("-----------------\n")
                click.echo("Agent Name: {}".format(agent_details['distro']))
                click.echo("Agent IP: {}".format(agent_details['distro']))
                click.echo("Agent UUID: {}".format(agent_details['uuid']))
                click.echo("Network UUID: {}".format(agent_details['network_uuid']))
                click.echo("Plugin Feed: {}".format(agent_details['plugin_feed_id']))

                click.echo("\nDistribution Information")
                click.echo("----------------------------\n")
                click.echo("Platform: {}".format(agent_details['platform']))
                click.echo("Distribution: {}".format(agent_details['distro']))
                click.echo("Core Version: {}".format(agent_details['core_version']))
                click.echo("Core Build: {}".format(agent_details['core_build']))

                click.echo("\nAgent Connection information")
                click.echo("----------------------------\n")
                click.echo("Last Connect Time: {}".format(agent_details['last_connect']))
                try:
                    click.echo("Last Scan Time: {}".format(agent_details['last_scanned']))
                except:
                    click.echo("Not Scanned Yet")
                click.echo("Restart Pending: {}".format(agent_details['restart_pending']))
                click.echo("Status: {}".format(agent_details['status']))

                click.echo("\nAgent Groups")
                click.echo("----------------------------\n")
                for agent_groups in agent_details['groups']:
                    click.echo("Group Name({}): {}".format(str(agent_groups['id']), str(agent_groups['name'])))
            except TypeError:
                click.echo("\nCommon...really? Focus...You need the Agent ID... Try again\n")
                exit()

        else:
            click.echo("\n*** To see Agent Details use: navi agent --aid <agent id> ***\n")
            click.echo("\n{:45s} {:12} {}".format("Agent Name", "Agent ID", "Group(id)s"))
            click.echo("-" * 150)

            for agent_info in tio.agents.list():
                groups_string = ''
                try:
                    for group in agent_info['groups']:
                        groups_string = groups_string + ", {}({})".format(group['name'], group['id'])
                except KeyError:
                    pass
                click.echo("{:45s} {:12} {}".format(textwrap.shorten(str(agent_info['name']), width=45),
                                                    str(agent_info['id']),
                                                    textwrap.shorten(groups_string[1:], width=90)))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@agent.command(help="Display Agent Groups and membership information ")
@click.option("--gid", default=None, help="Display the agents that are members of the group using the group ID")
def groups(gid):

    if gid:
        group_details = tio.agent_groups.details(gid)
        click.echo("\n{:85s} {:15} {:40}".format("Agent Name", "Agent ID", "UUID", "Status"))
        click.echo("-" * 150)

        for agent_info in group_details['agents']:
            click.echo("{:85s} {:15} {:40s}".format(textwrap.shorten(str(agent_info['name']), width=85),
                                                    str(agent_info['id']),
                                                    str(agent_info['uuid']), str(agent_info['status'])))

        click.echo()
    else:
        click.echo("\n*** To see group membership use: navi agent groups --gid <group id> ***\n")
        try:
            click.echo("\n{:45s} {:40s} {:10}".format("Group Name", "Group UUID", "Group ID"))
            click.echo("-" * 150)

            group_list = tio.agent_groups.list()

            for group in group_list:
                click.echo("{:45s} {:40s} {:10}".format(str(group['name']), str(group['uuid']), str(group['id'])))

            click.echo()
        except AttributeError:
            click.echo("\nCheck your permissions or your API keys\n")


@agent.command(help="Create a new Agent Group")
@click.option("--name", default=None, required=True, help="The name of the new Agent Group you want to create")
@click.option("--scanner", default=1, help="Add Agent Group to a specific scanner")
def create(name, scanner):
    try:
        group_creation = tio.agent_groups.create(name=name, scanner_id=scanner)
    
        click.echo("\nYour agent group: {} has been created.\n\nHere is the ID: {} and UUID : {}"
                   "\n".format(group_creation['name'], str(group_creation['id']), str(group_creation['uuid'])))
    except AttributeError:
        click.echo("Check your API Keys")


@agent.command(help="Add an agent to a Group")
@click.option("--aid", default=None, required=True, help="The agent ID of the agent you want to add ")
@click.option("--gid", default=None, required=True, help="The Group ID you want to add the agent(s) to.")
@click.option("--file", default=None, required=False, help="CSV with UUIDs as the first column.")
def add(aid, gid, file):

    if file:
        # ignore AID and use the file instead
        for agent_info in tio.agents.list():

            print(agent_info['uuid'], agent_info['id'])

        import csv
        with open(file, 'r', newline='') as new_file:
            agent_list = []
            add_agents = csv.reader(new_file)

            for rows in add_agents:
                # UUID will be in the first column
                agent_list.append(rows[0])

            for agent_info in tio.agents.list():
                agent_uuid = agent_info['uuid']
                agent_id = agent_info['id']
                if agent_uuid in agent_list:
                    # Add agents to the Group
                    tio.agent_groups.add_agent(gid, agent_id)
    else:
        # Add agent to Group
        tio.agent_groups.add_agent(gid, aid)

        click.echo("\nYour agent has been added to the Group ID: {}\n".format(gid))


@agent.command(help="Remove an Agent from a Agent Group")
@click.option("--aid", default=None, required=True, help="The agent ID of the agent you want to remove ")
@click.option("--gid", default=None, required=True, help="The Group ID you want to add the agent(s) to.")
def remove(aid, gid):
    try:
        # Remove an agent from a Group
        tio.agent_groups.delete_agent(gid, aid)

        click.echo("\nYour agent has been removed from the Group ID: {}\n".format(gid))
    except AttributeError:
        click.echo("Check your API Keys")


@agent.command(help="Unlink an by Agent ID")
@click.option("--aid", default=None, required=True, help="The Agent ID of the agent you want to unlink")
def unlink(aid):
    try:
        tio.agents.unlink(aid)
        click.echo("\nYour Agent: {} has been unlinked".format(aid))
    except AttributeError:
        click.echo("Check your API Keys")
