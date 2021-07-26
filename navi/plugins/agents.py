import click
from .api_wrapper import tenb_connection
import textwrap

tio = tenb_connection()


@click.group(help="Perform common tasks against Agents and Agent Groups")
def agent():
    pass


@agent.command(help="Display Agent information - Paired with Group IDs")
def display():
    try:
        click.echo("\n{:45s} {:15} {:40} {}".format("Agent Name", "Agent ID", "UUID", "Status", "Group(id)s"))
        click.echo("-" * 150)

        for agent_info in tio.agents.list():
            groups_string = ''
            try:
                for group in agent_info['groups']:
                    groups_string = groups_string + ", {}({})".format(group['name'], group['id'])
            except KeyError:
                pass
            click.echo("{:45s} {:15} {:40s} {}".format(textwrap.shorten(str(agent_info['name']), width=45),
                                                       str(agent_info['id']),
                                                       str(agent_info['uuid']), str(agent_info['status']),
                                                       textwrap.shorten(groups_string[1:], width=60)))
        click.echo()
    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")


@agent.command(help="Display Agent Groups")
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

        try:
            click.echo("\n{:45} {:40} {:10}".format("Group Name", "Group UUID", "Group ID"))
            click.echo("-" * 150)

            group_list = tio.agent_groups.list()

            for group in group_list:
                click.echo("{:45} {:40} {:10}".format(str(group['name']), str(group['uuid']), str(group['id'])))

            click.echo()
        except AttributeError:
            click.echo("\nCheck your permissions or your API keys\n")


@agent.command(help="Create a new Agent Group")
@click.option("--name", default=None, help="The name of the new Agent Group you want to create")
@click.option("--scanner", default=1, help="Add Agent Group to a specific scanner")
def create(name, scanner):
    group_creation = tio.agent_groups.create(name=name, scanner_id=scanner)

    click.echo("\nYour agent group: {} has been created.\n\nHere is the ID: {} and UUID : {}"
               "\n".format(group_creation['name'], str(group_creation['id']), str(group_creation['uuid'])))


@agent.command(help="Add an agent to a Group")
@click.option("--aid", default=None, help="The agent ID of the agent you want to add ")
@click.option("--gid", default=None, help="The Group ID you want to add the agent(s) to.")
def add(aid, gid):
    if gid:
        if aid:
            # Add agent to Group
            tio.agent_groups.add_agent(gid, aid)

            click.echo("\nYour agent has been added to the Group ID: {}".format(gid))


@agent.command(help="Remove an Agent from a Agent Group")
@click.option("--aid", default=None, help="The agent ID of the agent you want to remove ")
@click.option("--gid", default=None, help="The Group ID you want to add the agent(s) to.")
def remove(aid, gid):
    if gid:
        if aid:
            # Remove an agent from a Group
            tio.agent_groups.delete_agent(gid, aid)

            click.echo("\nYour agent has been removed from the Group ID: {}".format(gid))


@agent.command(help="Unlink an by Agent ID")
@click.option("--aid", default=None, help="The Agent ID of the agent you want to unlink")
def unlink(aid):
    if aid:
        tio.agents.unlink(aid)
        click.echo("\nYour Agent: {} has been unlinked".format(aid))
    else:
        click.echo("You have provide a agent ID")
