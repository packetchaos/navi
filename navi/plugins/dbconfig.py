from .database import new_db_connection, create_table


def create_keys_table():
    database = r"navi.db"
    key_conn = new_db_connection(database)
    key_table = """CREATE TABLE IF NOT EXISTS keys (
                            access_key text,
                            secret_key text
                            );"""
    create_table(key_conn, key_table)


def create_diff_table():
    database = r"navi.db"
    diff_conn = new_db_connection(database)
    diff_table = """CREATE TABLE IF NOT EXISTS diff (
                        update_id integer PRIMARY KEY,
                        timestamp text,
                        days text,
                        update_type text,
                        exid text);"""
    create_table(diff_conn, diff_table)


def create_software_table():
    database = r"navi.db"
    soft_conn = new_db_connection(database)
    soft_table = """CREATE TABLE IF NOT EXISTS software (
                        asset_uuid text,
                        software_string text);"""
    soft_conn.execute('pragma journal_mode=wal;')
    create_table(soft_conn, soft_table)


def create_vulns_table():
    database = r"navi.db"
    vuln_conn = new_db_connection(database)
    vuln_table = """CREATE TABLE IF NOT EXISTS vulns (
                            asset_ip text, 
                            asset_uuid text, 
                            asset_hostname text, 
                            first_found text, 
                            last_found text, 
                            output text, 
                            plugin_id text, 
                            plugin_name text, 
                            plugin_family text, 
                            port text, 
                            protocol text, 
                            severity text, 
                            scan_completed text, 
                            scan_started text, 
                            scan_uuid text, 
                            schedule_id text, 
                            state text,
                            cves text,
                            score text,
                            exploit text,
                            xrefs text,
                            synopsis text, 
                            see_also text,
                            solution text,
                            version text, 
                            description text, 
                            cvss3_base_score text,
                            cvss3_temporal_score text,
                            cvss_base_score text,
                            cvss_temporal_score text,
                            OSes text,
                            publication_date text,
                            patch_publication_date text,
                            url text
                            );"""
    vuln_conn.execute('pragma journal_mode=wal;')
    create_table(vuln_conn, vuln_table)


def create_assets_table():
    database = r"navi.db"
    asset_conn = new_db_connection(database)
    create_asset_table = """CREATE TABLE IF NOT EXISTS assets (
                            ip_address text,
                            hostname text,
                            fqdn text,
                            uuid text PRIMARY KEY,
                            first_found text,
                            last_found text, 
                            operating_system text,
                            mac_address text, 
                            agent_uuid text,
                            last_licensed_scan_date text,
                            network text,
                            acr text,
                            aes text,
                            aws_id text,
                            aws_ec2_instance_state text,
                            aws_ec2_name text,
                            aws_ec2_region text,
                            aws_availability_zone text,
                            gcp_instance_id text,
                            gcp_project_id text,
                            gcp_zone text,
                            azure_location text,
                            azure_resource_group text,
                            azure_resource_id text,
                            azure_subscription_id text,
                            azure_type text,
                            azure_vm_id text,
                            url text
                            );"""
    asset_conn.execute('pragma journal_mode=wal;')
    create_table(asset_conn, create_asset_table)


def create_tag_table():
    database = r"navi.db"
    tag_conn = new_db_connection(database)
    create_tags_table = """CREATE TABLE IF NOT EXISTS tags (
                        tag_id integer PRIMARY KEY,
                        asset_uuid text,
                        asset_ip text,
                        tag_key text,
                        tag_uuid text,
                        tag_value text,
                        tag_added_date text
                        );"""
    tag_conn.execute('pragma journal_mode=wal;')
    create_table(tag_conn, create_tags_table)


def create_tagrules_table():
    database = r"navi.db"
    tag_conn = new_db_connection(database)
    create_tags_table = """CREATE TABLE IF NOT EXISTS tagrules (
                        category_uunaviid text,
                        key text,
                        value_uuid text,
                        value text,
                        description text,
                        access text,
                        filters text
                        );"""
    tag_conn.execute('pragma journal_mode=wal;')
    create_table(tag_conn, create_tags_table)


def create_epss_table():
    database = r"navi.db"
    epss_conn = new_db_connection(database)
    create_score_table = """CREATE TABLE IF NOT EXISTS epss (
                        cve text PRIMARY KEY,
                        epss_value text,
                        percentile text
                        );"""
    epss_conn.execute('pragma journal_mode=wal;')
    create_table(epss_conn, create_score_table)


def create_apps_table():
    database = r"navi.db"
    app_conn = new_db_connection(database)
    create_apps = """CREATE TABLE IF NOT EXISTS apps (
                            name text,
                            uuid text PRIMARY KEY, 
                            target text, 
                            scan_completed_time text,
                            pages_crawled text,
                            requests_made text, 
                            critical_count text,
                            high_count text,
                            medium_count text,
                            low_count text, 
                            info_count text,
                            owasp text,
                            tech_list text,
                            config_id text,
                            notes text,
                            asset_uuid text
                            );"""
    app_conn.execute('pragma journal_mode=wal;')

    create_table(app_conn, create_apps)


def create_compliance_table():
    database = r"navi.db"
    compliance_conn = new_db_connection(database)
    create_compliance = """CREATE TABLE IF NOT EXISTS compliance (
                            asset_uuid text,
                            actual_value text,
                            audit_file text,
                            check_id text,
                            check_info text,
                            check_name text,
                            expected_value text,
                            first_seen text,
                            last_seen text,
                            plugin_id text,
                            reference text,
                            see_also text,
                            solution text,
                            status text 
                            );"""

    create_table(compliance_conn, create_compliance)


def create_fixed_table():
    database = r"navi.db"
    fixed_conn = new_db_connection(database)
    fixed_table = """CREATE TABLE IF NOT EXISTS fixed (
                            asset_uuid text,  
                            output text, 
                            plugin_id text, 
                            plugin_name text,  
                            port text,
                            first_found text,
                            last_fixed text,
                            last_found text,
                            severity text,
                            delta text,
                            pass_fail text,
                            state text,
                            special_url text
                            );"""
    fixed_conn.execute(fixed_table)


def create_plugins_table():
    database = r"navi.db"
    app_conn = new_db_connection(database)
    create_plugins = """CREATE TABLE IF NOT EXISTS plugins (
                            scan_uuid text,
                            name text,
                            cves text,
                            description text, 
                            family text, 
                            output text,
                            owasp text,
                            payload text,
                            plugin_id text,
                            plugin_mod_date text,
                            plugin_pub_date text,
                            proof text,
                            request_headers text,
                            response_headers text,
                            risk_factor text,
                            solution text,
                            url text,
                            xrefs text,
                            see_also text
                            );"""
    app_conn.execute('pragma journal_mode=wal;')

    create_table(app_conn, create_plugins)


def create_passwords_table():
    database = r"navi.db"
    ssh_conn = new_db_connection(database)
    ssh_table = """CREATE TABLE IF NOT EXISTS ssh (
                            username text,
                            password text
                            );"""
    create_table(ssh_conn, ssh_table)

