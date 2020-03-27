# How to Query the Navi.db directly

There are two commands that will help you get access to the database. 
There is no correction on SQL syntax so you will need to be precise with
your queries.


    navi find --query "<your query>"
    
    navi export --query "<your query>"

## Navi Databases and Tables
Vulns Database - 'vulns'

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
    
Assets Database - 'assets'

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

## Navi --query Examples

   
### Give me everything in the asset table
Find Command

    navi find --query "select * from assets;"

Export Command

    navi export --query "select * from assets;"
    
### Give me everything in the vulns table
Find Command

    navi find --query "select * from vulns;"

Export Command

    navi export --query "select * from vulns;"
 
### IP, mac, fqdn by plugin ID 19506
Use the find command first

    navi find --query "SELECT vulns.asset_ip, assets.fqdn, assets.mac_address 
    FROM vulns 
    LEFT OUTER JOIN assets 
    ON assets.ip_address = vulns.asset_ip where vulns.plugin_id='19506';"

Then you can export.  The columns will follow the order of your select statement

    navi export --query "SELECT vulns.asset_ip, assets.fqdn, assets.mac_address 
    FROM vulns 
    LEFT OUTER JOIN assets 
    ON assets.ip_address = vulns.asset_ip where vulns.plugin_id='19506';"
    
### IP, mac, fqdn by plugin ID 19506 but not 11219
Find command

    navi find --query "SELECT vulns.asset_ip, assets.fqdn, assets.mac_address 
    FROM vulns 
    LEFT OUTER JOIN assets 
    ON assets.ip_address = vulns.asset_ip where vulns.plugin_id='19506' 
    AND NOT vulns.plugin_id='11219';"

Export command

    navi export --query "SELECT vulns.asset_ip, assets.fqdn, assets.mac_address 
    FROM vulns 
    LEFT OUTER JOIN assets 
    ON assets.ip_address = vulns.asset_ip where vulns.plugin_id='19506' 
    AND NOT vulns.plugin_id='11219';"
