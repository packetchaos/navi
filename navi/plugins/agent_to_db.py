import click
from .database import new_db_connection, insert_agents
from .dbconfig import create_agents_table
from .api_wrapper import tenb_connection

tio = tenb_connection()


def download_agent_data():
    database = r"navi.db"
    agent_conn = new_db_connection(database)
    agent_conn.execute('pragma journal_mode=wal;')
    create_agents_table()
    with agent_conn:

        for agents in tio.agents.list():
            csv_list = []
            try:
                csv_list.append(agents['id'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['uuid'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['name'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['platform'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['ip'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['last_connect'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['plugin_feed_id'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['core_build'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['core_version'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['linked_on'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['last_connect'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['status'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['network_uuid'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['network_name'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['health'])
            except KeyError:
                csv_list.append(" ")

            try:
                csv_list.append(agents['health_state_name'])
            except KeyError:
                csv_list.append(" ")

            if csv_list:
                insert_agents(agent_conn, csv_list)
            else:
                click.echo(
                    "\nYou may not have permissions to the agent data or you have no agents in this container.\n")
                click.echo("Use 'navi explore api /scanners/1/agents' to validate your access\n")



