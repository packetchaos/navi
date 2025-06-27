import sqlite3
from sqlite3 import Error
import click
import re


# Define the regex function
def regexp(pattern, string):
    if string is None:
        return False
    return re.search(pattern, string) is not None


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
    try:
        # start = time.time()
        database = r"navi.db"
        query_conn = new_db_connection(database)
        with query_conn:
            query_conn.create_function("REGEXP", 2, regexp)
            cur = query_conn.cursor()
            cur.execute('pragma journal_mode=wal;')
            cur.execute('pragma cache_size=-100000;')
            cur.execute('PRAGMA synchronous = OFF')
            cur.execute('pragma threads=4')
            cur.execute(statement)

            data = cur.fetchall()
            # end = time.time()
            # total = end - start
        query_conn.close()
        # click.echo("Sql Query took: {} seconds".format(total))
        return data
    except Error as e:
        click.echo("\nDB ERROR:")
        click.echo("The SQL statement: {}\nCreated the following error: {}\n".format(statement, e))
        exit()


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
    sql = '''INSERT or REPLACE into compliance(
                                              asset_uuid, 
                                              actual_value, 
                                              audit_file, 
                                              check_id, 
                                              check_info, 
                                              check_name,
                                              expected_value, 
                                              first_seen, 
                                              last_seen, 
                                              plugin_id, 
                                              reference, 
                                              see_also, 
                                              solution, 
                                              status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mod=wal;')
    cur.execute(sql, compliance)


def insert_zipper(conn, zipper):
    sql = '''INSERT or IGNORE into zipper(
                                          plugin_id,
                                          epss_value) VALUES(?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mod=wal;')
    cur.execute(sql, zipper)


def insert_assets(conn, assets):
    sql = '''INSERT or REPLACE into assets(
                                          ip_address, 
                                          hostname, 
                                          fqdn, 
                                          uuid, 
                                          first_found, 
                                          last_found, 
                                          operating_system,
                                          mac_address,
                                          netbios_names, 
                                          agent_uuid, 
                                          last_licensed_scan_date, 
                                          network, 
                                          acr, 
                                          aes, 
                                          aws_id,
                                          aws_ec2_instance_state,
                                          aws_ec2_name,
                                          aws_ec2_region,
                                          aws_availability_zone,
                                          gcp_instance_id,
                                          gcp_project_id,
                                          gcp_zone,
                                          azure_location,
                                          azure_resource_group,
                                          azure_resource_id,
                                          azure_subscription_id,
                                          azure_type,
                                          azure_vm_id,
                                          url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, assets)


def insert_agents(conn, agents):
    sql = '''INSERT or IGNORE into agents(
                                          agent_id, 
                                          agent_uuid, 
                                          hostname, 
                                          platform, 
                                          ip_address, 
                                          last_scanned, 
                                          plugin_feed_id,
                                          core_build, 
                                          core_version, 
                                          linked_on, 
                                          last_connect, 
                                          status, 
                                          network_uuid, 
                                          network_name,
                                          health_score,
                                          health_state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, agents)


def insert_certificates(conn, certs):
    sql = '''INSERT or IGNORE into certs(
                                        asset_uuid,
                                        subject_name,  
                                        country,  
                                        state_province,  
                                        locality,  
                                        organization,  
                                        common_name,  
                                        issuer_name,  
                                        organization_unit,  
                                        serial_number,  
                                        version,  
                                        signature_algorithm,  
                                        not_valid_before,  
                                        not_valid_after,    
                                        algorithm,  
                                        key_length,  
                                        signature_length) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, certs)


def insert_tags(conn, tags):
    sql = '''INSERT or IGNORE into tags(tag_id, asset_uuid, asset_ip, tag_key, tag_uuid, tag_value, tag_added_date)
     VALUES(?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, tags)


def insert_tag_rules(conn, tag_rules):
    sql = '''INSERT or IGNORE into tagrules(category_uuid, key, value_uuid, value, description, access, filters)
     VALUES(?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, tag_rules)


def insert_software(conn, software):
    sql = '''INSERT or IGNORE into software(software_string, asset_uuid) VALUES(?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, software)


def drop_tables(conn, table):
    try:
        drop_table = '''DROP TABLE {}'''.format(table)
        cur = conn.cursor()
        cur.execute('pragma journal_mode=wal;')
        cur.execute(drop_table)
    except Error:
        pass


def insert_vulns(conn, vulns):
    sql = '''INSERT or REPLACE into vulns(
                            finding_id,
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
                            exploit,
                            xrefs,
                            synopsis,
                            solution,
                            version, 
                            description, 
                            OSes,
                            url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''

    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, vulns)


def insert_apps(conn, apps):
    sql = '''INSERT or IGNORE into apps(
             name,
             uuid, 
             target, 
             scan_completed_time,
             pages_crawled,
             requests_made, 
             critical_count,
             high_count,
             medium_count,
             low_count, 
             info_count,
             owasp,
             tech_list,
             config_id,
             notes,
             asset_uuid)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, apps)


def insert_fixed(conn, fixed):
    sql = '''INSERT or IGNORE into fixed(
                            asset_uuid, 
                            output, 
                            plugin_id, 
                            plugin_name, 
                            port,
                            first_found,
                            last_fixed,
                            last_found,
                            severity,
                            delta,
                            pass_fail,
                            state,
                            special_url
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)'''

    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, fixed)


def insert_findings(conn, findings):
    sql2 = '''INSERT or IGNORE into findings(
            scan_uuid,
            name,
            cves,
            description, 
            family, 
            output,
            owasp,
            payload,
            plugin_id,
            plugin_mod_date,
            plugin_pub_date,
            proof,
            request_headers,
            response_headers,
            risk_factor,
            solution,
            url,
            xrefs,
            see_also)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur2 = conn.cursor()
    cur2.execute('pragma journal_mode=wal;')
    cur2.execute(sql2, findings)


def insert_epss(conn2, epss_data):
    sql_epss = '''INSERT or IGNORE into epss(
                            cve,
                            epss_value,
                            percentile) VALUES(?,?,?)'''
    epss_cur = conn2.cursor()
    epss_cur.execute('pragma journal_mode=wal;')
    epss_cur.execute(sql_epss, epss_data)


def insert_vuln_router(conn2, route_data):
    sql_router = '''INSERT or IGNORE into vuln_route(
                            route_id,
                            app_name,
                            plugin_list,
                            total_vulns,
                            vuln_type) VALUES(?,?,?,?,?)'''
    epss_cur = conn2.cursor()
    epss_cur.execute('pragma journal_mode=wal;')
    epss_cur.execute(sql_router, route_data)


def insert_vuln_paths(conn2, path_data):
    sql_router = '''INSERT or IGNORE into vuln_paths(
                            path_id,
                            plugin_id,
                            path,
                            asset_uuid) VALUES(?,?,?,?)'''
    epss_cur = conn2.cursor()
    epss_cur.execute('pragma journal_mode=wal;')
    epss_cur.execute(sql_router, path_data)


def insert_plugins(conn, exploit_data):
    sql_plugins = '''INSERT OR IGNORE into plugins(
                     plugin_id,
                     severity,
                     cves,
                     vpr_score,
                     exploit_available,
                     xrefs,
                     see_also,
                     cvss3_base_score,
                     cvss3_temporal_score,
                     cvss_base_score,
                     publication_date,
                     patch_publication_date,
                     exploit_framework_canvas,
                     exploit_framework_core,
                     exploit_framework_d2_elliot,
                     exploit_framework_exploithub,
                     exploit_framework_metasploit,
                     exploitability_ease,
                     exploited_by_malware,
                     exploited_by_nessus,
                     has_patch,
                     has_workaround,
                     in_the_news,
                     modification_date,
                     name,
                     risk_factor,
                     threat_intensity_last28,
                     threat_sources_last28,
                     cvss_impact_score_predicted,
                     cvss3_impact_score,
                     lower_bound,
                     upper_bound,
                     vpr_updated,
                     cpe,
                     url
                     ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    exploit_cur = conn.cursor()
    exploit_cur.execute('pragma journal_mode=wal;')
    exploit_cur.execute(sql_plugins, exploit_data)