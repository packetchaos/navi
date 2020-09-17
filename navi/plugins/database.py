import sqlite3
from sqlite3 import Error
import click


def new_db_connection(db_file):
    # create a connection to our database
    conn = None
    try:
        # A database file will be created if one doesn't exist
        conn = sqlite3.connect(db_file, timeout=60.0)
    except Error as E:
        click.echo(E)
    return conn


def create_table(conn, table_information):
    try:
        c = conn.cursor()
        c.execute('pragma journal_mode=wal;')
        c.execute(table_information)
    except Error as e:
        click.echo(e)


def insert_assets(conn, assets):
    sql = '''INSERT or IGNORE into assets(ip_address, hostname, fqdn, uuid, first_found, last_found, operating_system,
                       mac_address, agent_uuid, last_licensed_scan_date, network, acr, aes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, assets)


def insert_tags(conn, tags):
    sql = '''INSERT or IGNORE into tags(tag_id, asset_uuid, asset_ip, tag_key, tag_uuid, tag_value, tag_added_date) VALUES(?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, tags)


def drop_tables(conn, table):
    try:
        drop_table = '''DROP TABLE {}'''.format(table)
        cur = conn.cursor()
        cur.execute('pragma journal_mode=wal;')
        cur.execute(drop_table)
    except Error:
        pass


def insert_vulns(conn, vulns):
    sql = '''INSERT or IGNORE into vulns(
                            navi_id,
                            asset_ip, 
                            asset_uuid, 
                            asset_hostname, 
                            first_found, 
                            last_found, 
                            output, 
                            plugin_id, 
                            plugin_name, 
                            plugin_family, 
                            port, 
                            protocol, 
                            severity, 
                            scan_completed, 
                            scan_started, 
                            scan_uuid, 
                            schedule_id, 
                            state
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''

    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, vulns)


def insert_apps(conn, apps):
    sql = '''INSERT or IGNORE into apps(
             name,
             uuid, 
             target, 
             scan_completed_time,
             pages_audited,
             pages_crawled,
             requests_made, 
             critical_count,
             high_count,
             medium_count,
             low_count, 
             info_count,
             owasp,
             tech_list,
             config_id)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, apps)
