# How to Query the Navi.db directly

There are two commands that will help you get access to the database. 
There is no correction on SQL syntax so you will need to be precise with
your queries.


    navi find query "<your query>"
    
    navi export query "<your query>"

## Navi Tables
Vulns table - 'vulns'

    navi_id integer PRIMARY KEY
    asset_ip text
    asset_uuid text
    asset_hostname text
    first_found text
    last_found text
    output text
    plugin_id text
    plugin_name text
    plugin_family text 
    port text
    protocol text
    severity text
    scan_completed text
    scan_started text
    scan_uuid text
    schedule_id text
    state text
    
Assets Table - 'assets'

    ip_address text
    hostname text
    fqdn text
    uuid text PRIMARY KEY
    first_found text
    last_found text
    operating_system text
    mac_address text 
    agent_uuid text
    last_licensed_scan_date text
    network text

Tags Table - 'tags'

    tag_id integer PRIMARY KEY,
    asset_uuid text,
    asset_ip,
    tag_key text,
    tag_uuid text,
    tag_value text,
    tag_added_date text

Compliance Table - 'compliance'

    asset_uuid text
    actual_value text
    audit_file text
    check_id text
    check_info text
    check_name text
    expected_value text
    first_seen text
    last_seen text
    plugin_id text
    reference text
    see_also text
    solution text
    status text  

Was Table - 'apps'

    name text
    uuid text PRIMARY KEY 
    target text
    scan_completed_time text
    pages_audited text
    pages_crawled text
    requests_made text 
    critical_count text
    high_count text
    medium_count text
    low_count text 
    info_count text
    owasp text
    tech_list text
    config_id text

## Navi --query Examples

   
### Give me everything in the asset table
Find Command

    navi explore data query "select * from assets;"

Export Command

    navi export query "select * from assets;"
    
### Give me everything in the vulns table
Find Command

    navi explore data query "select * from vulns;"

Export Command

    navi export query "select * from vulns;"
 
### IP, mac, fqdn by plugin ID 19506
Use the find command first

    navi explore data query "SELECT vulns.asset_ip, assets.fqdn, assets.mac_address 
    FROM vulns 
    LEFT OUTER JOIN assets 
    ON assets.ip_address = vulns.asset_ip where vulns.plugin_id='19506';"

Then you can export.  The columns will follow the order of your select statement

    navi export query "SELECT vulns.asset_ip, assets.fqdn, assets.mac_address 
    FROM vulns 
    LEFT OUTER JOIN assets 
    ON assets.ip_address = vulns.asset_ip where vulns.plugin_id='19506';"
    
### IP, mac, fqdn by plugin ID 19506 but not 11219
Find command

    navi explore data query "SELECT vulns.asset_ip, assets.fqdn, assets.mac_address 
    FROM vulns 
    LEFT OUTER JOIN assets 
    ON assets.ip_address = vulns.asset_ip where vulns.plugin_id='19506' 
    AND NOT vulns.plugin_id='11219';"

Export command

    navi export query "SELECT vulns.asset_ip, assets.fqdn, assets.mac_address 
    FROM vulns 
    LEFT OUTER JOIN assets 
    ON assets.ip_address = vulns.asset_ip where vulns.plugin_id='19506' 
    AND NOT vulns.plugin_id='11219';"


### Export FQDN and ALl compliance information for a given UUID

    navi export query "SELECT assets.fqdn, compliance.* 
    FROM compliance 
    LEFT OUTER JOIN assets 
    ON assets.uuid = compliance.asset_uuid 
    where asset_uuid='<uuid>';"

### Count Vulns or Assets using SQL
Asset Total

    navi explore data query "select count(uuid) from assets;"

Vulnerability Total

    navi explore data query "select count(*) from vulns where severity !='info';"

### Export Vuln data along EPSS data by cve
    navi export query "select e.epss_value, v.* from vulns v inner JOIN epss e ON v.cves LIKE '%'|| e.cve ||'%' where v.cves LIKE '%CVE-1999-0632%';"
