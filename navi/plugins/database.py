import sqlite3
from sqlite3 import Error
import click
# import time


def new_db_connection(db_file):
    # create a connection to our database
    conn = None
    try:
        # A database file will be created if one doesn't exist
        conn = sqlite3.connect(db_file, timeout=10.0)
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


def db_query(statement):
    # start = time.time()
    database = r"navi.db"
    query_conn = new_db_connection(database)
    with query_conn:
        cur = query_conn.cursor()
        cur.execute('pragma journal_mode=wal;')
        cur.execute('pragma cache_size=-10000;')
        cur.execute('PRAGMA synchronous = OFF')
        cur.execute('pragma threads=4')
        cur.execute(statement)

        data = cur.fetchall()
        # end = time.time()
        # total = end - start
    query_conn.close()
    # click.echo("Sql Query took: {} seconds".format(total))
    return data


def get_last_update_id():
    database = r"navi.db"
    conn = new_db_connection(database)
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT update_id from diff;")
            data = cur.fetchall()

            new_id = len(data) + 1
    except Error:
        new_id = 1
    return new_id


def insert_update_info(conn, diff):
    sql = '''INSERT or IGNORE into diff(update_id, timestamp, days, update_type, exid) VALUES(?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, diff)


def insert_compliance(conn, compliance):
    sql = '''INSERT or IGNORE into compliance(asset_uuid, actual_value, audit_file, check_id, check_info, check_name, 
                    expected_value, first_seen, last_seen, plugin_id, reference, see_also, solution, status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mod=wal;')
    cur.execute(sql, compliance)


def insert_assets(conn, assets):
    sql = '''INSERT or IGNORE into assets(ip_address, hostname, fqdn, uuid, first_found, last_found, operating_system,
                       mac_address, agent_uuid, last_licensed_scan_date, network, acr, aes, aws_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
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
                            state,
                            cves,
                            score,
                            exploit
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''

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



