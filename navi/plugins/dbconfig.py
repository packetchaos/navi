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
                            finding_id text PRIMARY KEY,
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
                            solution text,
                            version text, 
                            description text,
                            OSes text,
                            url text
                            );"""
    vuln_conn.execute('pragma journal_mode=wal;')
    create_table(vuln_conn, vuln_table)


def create_tone_findings_table():
    database = r"navi.db"
    tone_vuln_conn = new_db_connection(database)
    tone_findings_table = """CREATE TABLE IF NOT EXISTS tone_findings (
                            asset_id text,
                            finding_id PRIMARY KEY,
                            state text,
                            last_updated text,
                            first_observed_at text,
                            last_observed_at text,
                            last_fixed_at text,
                            port text,
                            protocol text,
                            cpes text,
                            finding_parent_detection_id text,
                            finding_detection_id text,
                            finding_provider_code text,
                            finding_product_code text,
                            finding_provider_detection_id text,
                            finding_detection_code text,
                            finding_detection_version text,
                            finding_detection_variant text,
                            finding_detection_sub_category text,
                            finding_resource_type text,
                            finding_detection_family text,
                            finding_detection_type text,
                            finding_intel_type text,
                            finding_name text,
                            finding_synopsis text,
                            finding_description text,
                            finding_solution text,
                            finding_script_file_name text,
                            finding_exploit_maturity text,
                            finding_detection_published_at text,
                            finding_vuln_published_at text,
                            finding_patch_published_at text,
                            finding_first_covered_at text,
                            finding_first_functional_exploit_at text,
                            finding_first_poc_at text,
                            finding_cisa_kev_added_date text,
                            finding_cisa_kev_due_date text,
                            finding_epss_scored_at text,
                            finding_severity_driver text,
                            finding_severity text,
                            finding_severity_level text,
                            finding_risk_factor text,
                            finding_risk_severity_level text,
                            finding_vpr_score text,
                            finding_vpr2_score text,
                            finding_vpr_risk_factor text,
                            finding_vpr_severity_level text,
                            finding_exploitability_ease_code text,
                            finding_exploitability_ease text,
                            finding_cvss2_source text,
                            finding_cvss2_base_score text,
                            finding_cvss2_base_vector text,
                            finding_cvss2_temporal_score text,
                            finding_cvss2_temporal_vector text,
                            finding_cvss3_source text,
                            finding_cvss3_base_score text,
                            finding_cvss3_base_vector text,
                            finding_cvss3_temporal_score text,
                            finding_cvss3_temporal_vector text,
                            finding_cvss4_source text,
                            finding_cvss4_score text,
                            finding_cvss4_vector text,
                            finding_cvss4_threat_metrics text,
                            finding_epss_score text,
                            finding_epss_percentile text,
                            finding_stig_severity text,
                            finding_is_security_control text,
                            finding_is_deprecated text,
                            finding_cves text,
                            finding_cwes text,
                            finding_metadata_file_name text,
                            asset_name text,
                            asset_class text,
                            acr text,
                            aes text,
                            is_licensed text,
                            total_finding_count text,
                            fixed_finding_count text,
                            sensor_type text
                            );"""
    tone_vuln_conn.execute('pragma journal_mode=wal;')
    create_table(tone_vuln_conn, tone_findings_table)


def create_plugins_table():
    database = r"navi.db"
    plugin_conn = new_db_connection(database)
    plugins_table = """CREATE TABLE IF NOT EXISTS plugins (
                              plugin_id text PRIMARY KEY,
                              severity text,
                              cves text,
                              vpr_score text,
                              exploit_available text,
                              xrefs text,
                              see_also text,
                              cvss3_base_score text,
                              cvss3_temporal_score text,
                              cvss_base_score text,
                              publication_date text,
                              patch_publication_date text,
                              exploit_framework_canvas text,
                              exploit_framework_core text,
                              exploit_framework_d2_elliot text,
                              exploit_framework_exploithub text,
                              exploit_framework_metasploit text,
                              exploitability_ease text,
                              exploited_by_malware text,
                              exploited_by_nessus text,
                              has_patch text,
                              has_workaround text,
                              in_the_news text,
                              modification_date text,
                              name text,
                              risk_factor text,
                              threat_intensity_last28 text,
                              threat_sources_last28 text,
                              cvss_impact_score_predicted text,
                              cvss3_impact_score text,
                              lower_bound text,
                              upper_bound text,
                              vpr_updated text,
                              cpe text,
                              url text);"""
    plugin_conn.execute('pragma journal_mode=wal;')
    create_table(plugin_conn, plugins_table)


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
                            netbios_names text, 
                            agent_uuid text,
                            last_licensed_scan_date text,
                            network text,
                            acr text,
                            aes integer,
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


def create_tone_assets_table():
    database = r"navi.db"
    tone_asset_conn = new_db_connection(database)
    create_tone_asset_table = """CREATE TABLE IF NOT EXISTS tone_assets(
                                 acr text,  
                                 aes text, 
                                 asset_class text, 
                                 asset_id PRIMARY KEY, 
                                 asset_name text, 
                                 cloud_id_name text, 
                                 created_at text, 
                                 critical_vuln_count text, 
                                 critical_weakness_count text, 
                                 entitlement_count text, 
                                 exposure_classes text, 
                                 first_observed_at text, 
                                 fqdns text, 
                                 high_vuln_count text, 
                                 high_weakness_count text, 
                                 is_licensed text, 
                                 last_licensed_at text, 
                                 last_observed_at text, 
                                 last_updated text, 
                                 license_expires_at text, 
                                 low_vuln_count text, 
                                 low_weakness_count text, 
                                 medium_vuln_count text, 
                                 medium_weakness_count text, 
                                 sensors text, 
                                 sources text, 
                                 tag_count text, 
                                 tag_ids text, 
                                 tenable_uuid text, 
                                 total_weakness_count text,
                                 host_name text, 
                                 ipv4_addresses text, 
                                 ipv6_addresses text, 
                                 operating_systems text, 
                                 external_identifier text, 
                                 external_tags text, 
                                 mac_addresses text, 
                                 custom_attributes text, 
                                 total_finding_count text
                                 );"""
    tone_asset_conn.execute('pragma journal_mode=wal;')
    create_table(tone_asset_conn, create_tone_asset_table)


def create_agents_table():
    database = r"navi.db"
    agent_conn = new_db_connection(database)
    create_agent_table = """CREATE TABLE IF NOT EXISTS agents (
                            agent_id text, 
                            agent_uuid text, 
                            hostname text, 
                            platform text, 
                            ip_address text, 
                            last_scanned text, 
                            plugin_feed_id text,
                            core_build text, 
                            core_version text, 
                            linked_on text, 
                            last_connect text, 
                            status text, 
                            network_uuid text, 
                            network_name text,
                            health_score text,
                            health_state text
                            );"""
    agent_conn.execute('pragma journal_mode=wal;')
    create_table(agent_conn, create_agent_table)


def create_certs_table():
    database = r"navi.db"
    cert_conn = new_db_connection(database)
    create_cert_table = """CREATE TABLE IF NOT EXISTS certs (
                        asset_uuid text,
                        subject_name text,  
                        country text,  
                        state_province text,  
                        locality text,  
                        organization text,  
                        common_name text,  
                        issuer_name text,  
                        organization_unit text,  
                        serial_number text,  
                        version text,  
                        signature_algorithm text,  
                        not_valid_before text,  
                        not_valid_after text,    
                        algorithm text,  
                        key_length text,  
                        signature_length text);"""
    cert_conn.execute('pragma journal_mode=wal;')
    create_table(cert_conn, create_cert_table)


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


def create_sla_table():
    database = r"navi.db"
    conn = new_db_connection(database)
    create_sla_table = """CREATE TABLE IF NOT EXISTS sla (
                                critical text,
                                high text,
                                medium text, 
                                low text 
                                );"""
    create_table(conn, create_sla_table)


def create_zipper_table():
    database = r"navi.db"
    zipper_conn = new_db_connection(database)
    zipper_table = """CREATE TABLE IF NOT EXISTS zipper (
                        plugin_id text PRIMARY KEY,
                        epss_value text
                        );"""
    zipper_conn.execute('pragma journal_mode=wal;')
    create_table(zipper_conn, zipper_table)


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


def create_findings_table():
    database = r"navi.db"
    app_conn = new_db_connection(database)
    create_findings = """CREATE TABLE IF NOT EXISTS findings (
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

    create_table(app_conn, create_findings)


def create_passwords_table():
    database = r"navi.db"
    ssh_conn = new_db_connection(database)
    ssh_table = """CREATE TABLE IF NOT EXISTS ssh (
                            username text,
                            password text
                            );"""
    create_table(ssh_conn, ssh_table)


def create_vuln_route_table():
    database = r"navi.db"
    vuln_route_conn = new_db_connection(database)
    route_table = """CREATE TABLE IF NOT EXISTS vuln_route (
                            route_id integer Primary Key,
                            app_name text,
                            plugin_list text,
                            total_vulns INTEGER,
                            vuln_type text
                            );"""
    create_table(vuln_route_conn, route_table)


def create_vuln_path_table():
    database = r"navi.db"
    vuln_path_conn = new_db_connection(database)
    path_table = """CREATE TABLE IF NOT EXISTS vuln_paths (
                            path_id integer Primary Key,
                            plugin_id text,
                            path text,
                            asset_uuid text,
                            finding_id text
                            );"""
    create_table(vuln_path_conn, path_table)
