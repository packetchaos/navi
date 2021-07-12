# Navi - The Tenable.io Swiss Army Knife
A command-line tool which leverages the Tenable.io API to automate common tasks
in Cyber Exposure or Vulnerability Management.

    *** This tool is not an officially supported Tenable project ***
    
    *** Use of this tool is subject to the terms and conditions identified below,
     and is not subject to any license agreement you may have with Tenable ***

## Important Notes

    Navi is being converted to use pytenable as it's base.  Many of the commands
    have already been converted to using pytenable.

Navi will download the entire data-set(90 days) locally after API keys are
entered and the update command is used! To download Vulnerability data and Asset data you have to be an Administrator in Tenable.io.

All Vulns and All Assets are downloaded into a SQLLITE database named navi.db in the current directory.
 
 Most of the API calls nessessary to make navi work require access to
 your all of the available data.  Tenable.io has a 5000 record limit so Navi utilizes the Export API.
 
 The data will not be updated until you run the update command.  Keep this in mind when adding elements to Tenable.io like Tags.
 Compliance data will need to be downloaded seperately as it is not apart of the update full process.
 
    navi update full
    
 Alternatively you can select which export you want to update:
 
    navi update assets
    
    navi update vulns
    
    navi update compliance
    
    navi update was
 
 Furthermore, you can limit how much data is downloaded by using the --days command
 
    navi update assets --days 2
 
 You can even specify your export id.
 
    navi update vulns --exid 123456-987654-asdfgh-jklopi-ididis
    
 You can also control the amount of threads used for downlaods (1-10)
 The Default thread value is 10.
 
    navi update compliance --threads 4

# Common Issues

### My Docker container keeps getting "Killed"
Navi uses threading, to speed up downloads; It pulls 50 asset chunks on 10 threads and since the vulnerabilities per asset
fluctuate this can spike the memory above 2G.  If this happens increase your memeory to 4G for under 10,000 assets and 8Gb for larger asset counts..

[Directions for Mac](https://docs.docker.com/docker-for-mac/#memory)

[Directions for Windows](https://docs.docker.com/docker-for-windows/#advanced)
 
### I keep getting DB locks
I'm still working on a fix for large accounts, those over 100K assets.  For now use the thread option to avoid DB locks by reducing it to 1. Increasing your RAM and running Navi on SSDs will speed help avoid DB locks.

    navi update full --threads 1
 
### What is my Navi Version
Versions older than 5.1.36 do not have this feature.

    navi display -version

### Are my Keys inputted correctly?
In different terminals it can be a challenge to copy the keys to navi since you can not be sure it copied correctly.  

Use the below commands to check your keys
    
    navi find query "select * from keys;"

Alternatively, you could try entering your keys again using the '-clear' command to see what is being copied to the screen.

    navi keys -clear

### What is the biggest Tenable.io instance Navi has been tested on?
Navi 6.3.0 was recently tested on a container with 250,000 assets and 41 million vulnerabilties.  
It took 30 mins for t.io to prepare the download and 30 mins to download and parse the data
 into navi.db which ended up being 31GB.  Plugin queries took 2secs where looking for text in an output took 2mins.

 6.2.3 and later improves query performance by a factor of 10 with the below changes.
 * Three indexes where added to reduce vuln query time
 * Exports were reduced to 50 from 500 assets to increase download time
 * Synchronous was turned off to speed up downloads
 * DB cache was increased to 10000 from 2000 default in SQLite
    

# Download and Configure navi in a Docker Container

    docker pull silentninja/navi:latest
  
    docker run -it -p 8000:8000 silentninja/navi:latest /bin/bash 

    navi keys
    
    navi update full
  
## Detach from Container
    CTR+Q+P - CTR+Q+P

## Attach to Contianer
    docker attach <container id>
  
    <press enter>

## Configure Docker Container For Reporting
Navi has a few reporting capabilities where a CSV is the output.  To extract this data from the container you will need to launch the container with port 8000 exposed and use the 'http' command to extract the reports.

    docker run -it -p 8000:8000 silentninja/navi:latest /bin/bash

### Extract Data from the Docker Container
To extract data from the container you need to run an http server.  Use the below built in command.

    navi http

 * Navigate to the website: http://127.0.0.1:8000
 * Simply download the item you want by clicking on it.
 
# Download Navi from PyPI - navi-pro
## Prepare your Machine
 * Install [Python3](https://realpython.com/installing-python/)
 
## Install Navi using pip

    pip3 install navi-pro

## Uninstall Navi using pip

    pip3 uninstall navi-pro

# Navi General Usage
Before you begin you need the Keys! The program will continue to error out without valid API keys.
Note: The keys will not show up on the screen; similar to a password prompt.

    navi keys

Alternatively, to support automation, you can add your keys with a single command

    navi keys --a your-access-key  --s your-secret-key

There are 25 core commands:
 * add        Manually add an asset to Tenable.io
 * agroup     Create an Access group Based on a Tag or Agent Group
 * api        Test the API ex: scans
 * cs         Interact with the Container Security API
 * delete     Delete objects from Tenable IO
 * display    Display or Print information found in Tenable.io
 * export     Export Tenable.io Data
 * find       Discover what is in Tenable.io
 * http       Spin up a http server to extract data from the Docker container
 * ip         Get IP specific information
 * keys       Enter or Reset your Keys
 * listen     Open up a Netcat listener to accept files over port 8000
 * lumin      Adjust ACRs in Lumin by tag
 * mac        Enter in a Mac Address to find the Manufacturer
 * mail       Mail yourself a Report
 * network    Create, Change Networks or Display Assets in a network
 * portal     A web interface to explore the navi DB [BETA- Doesn't work in...
 * scan       Create and Control Scans
 * smtp       Enter or Overwrite your SMTP information
 * tag        Create a Tag Category/Value Pair
 * tgroup     Create a Target Group
 * update     Update local repository
 * user       Enable, Disable or add users
 * usergroup  Create a group or Add/remove a user from a group
 * was        Interact with WAS V2 API
 * migrate    Migrate AWS tags to T.io tags

## Explore the Tenable.io API - 'api'
  In many cases, it is useful to see the data behind an api endpoint
  either to plan for automation and development or for troubleshooting
  an issue. Using the 'api' command allows you to send a 'GET' request to
  Tenable.io and return json data using the pprint.

  Enter in a API endpoint and get a pretty print json ouput.  Try some of the below endpoints:
  Note: You do not need to include the first slash '/' in your request. so '/scans' becomes 'scans'
   * scans
   * scanners
   * users

### api - examples

    navi api /scans 

    navi api /scanners
    
    navi api /users
    
    navi api /workbenches/assets
  
## IP address queries - 'ip'
NOTE: 6.4.14 and later support using a UUID instead of an IP.

The majority of the options in the ip command are using the plugin output.
This is the fastest way to get access to the most important data in
    vulnerability management and/or remediation activities.

When a you're trying to chase down a vulnerability or addressing risk
    on a certain asset, you have lots of questions about the asset.

  * What software is on the asset? `navi ip 192.168.1.100 -software`
  * When was the last reboot(WMI)? `navi ip 192.168.1.100 --plugin 56467`
  * When was the last scan? `navi ip 192.168.128.100 --plugin 19506`
  * Was the last scan authenticated? `navi ip 192.168.128.100 --plugin 19506`
  * What ports are open? `navi ip 192.168.128.100 --plugin 11219`
  * Who owns this asset(using Tags)? `navi ip 192.168.128.100 -details`
    
All of these questions are answerable using the 'ip' command to  
discover asset related information very quickly.

  * --plugin TEXT --> Find Details on a particular plugin ID
  * -n -->            Netstat Established and Listening and Open Ports(requires verbosity)
  * -p -->            Patch Information
  * -t -->            Trace Route
  * -o -->            Process Information
  * -c -->            Connection Information
  * -s -->            Services Running(requires verbosity)
  * -r -->            Local Firewall Rules(requires verbosity)
  * -d -->            Scan Detail: 19506 plugin output
  * -patches -->      Missing Patches
  * -software -->     Find software installed on Unix of windows hosts
  * -outbound -->     Display outbound connections found by NNM
  * -exploit -->      Display exploitable vulnerabilities
  * -critical -->     Display critical vulnerabilities
  * -details -->      Details on an Asset: IP, UUID, Vulns, etc
  * -vulns -->        Display all vulnerabilities and their plugin IDs
  * -info -->         Display all info plugins and their IDs
  * -cves -->         Display all cves found on the asset
  * -compliance -->   Display all compliance findings for a given UUID

### ip - Examples

    navi ip 192.168.1.1 --plugin 19506

    navi ip 192.168.1.1 -details -software
    
    navi ip 1a955d70-468e-4667-b558-e7559c5cec54 -vulns
    
    navi ip 1a955d70-468e-4667-b558-e7559c5cec54 -compliance

## Find information - 'find'

While the 'ip' command helps find unknown information on known assets.  The
'find' command helps identify the unknown information on unknown assets.  For
instance, consider the following questions and the time it may take for you to
answer them.

  * What assets have port 21/ftp open? `navi find port 21`
  * How many assets took longer than 20 mins to scan? `navi find scantime 20`
  * Where are credential failures happening? `navi find creds`
  * What assets are running Docker? `navi find docker`
  * What assets have java vulnerabilities? `navi find name java`
  * What linux assets have splunk package installed? `navi find plugin 22869 --output "splunk"`

All of these answers are discoverable using the find command.  While it
is not a panacea at scale, it can help identify if the question at hand
is worth your time to investigate.  To explain, if you run the `navi find port 21`
command and find nothing vs finding 1000s, your action may change dramatically.


  * creds  -->    Find Assets with Credential Issues using plugin 104410
  * cves   -->    Find Assets that have a given CVE
  * docker  -->   Find Docker Hosts using plugin 93561
  * ghost   -->   Find Assets that have not been scanned in any Cloud
  * name    -->   Find Assets with a given port open
  * plugin  -->   Find Assets where a plugin fired
  * port    -->   Find Assets with a given port open
  * query   -->   Find Assets with a given port open
  * scantime -->   Find Assets where a plugin fired
  * webapp   -->  Find Potential Web Apps using plugin 1442 and 22964


## Container Security Information - 'cs'
  * report TEXT    -->     Display Vulns of CVSS 7 or above by Container ID.
  * comply TEXT   -->      Check to see if your container complies with your Policy

### cs - Examples

    navi cs report  48b5124b2768

    navi cs comply 48b5124b2768


## Display - Common Information - 'display'

All of the display commands send a basic 'GET' request to the applicable
API endpoint and present the most useful data in a friendly format.  This
command is great for confirming a change you made using navi.  For instance,
if you added a user, is the user enabled?

  * scanners     -->         List all of the Scanners</pre>
  * users         -->        List all of the Users
  * exclusions    -->        List all Exclusions
  * containers   -->         List all containers and their Vulnerability  Scores
  * logs        -->          List The actor and the action in the log file
  * running     -->          List the running Scans
  * scans       -->          List all Scans
  * nnm       -->       Nessus Network Monitor assets and their vulnerability scores
  * assets    -->       Assets found in the last 30 days
    * --tag -->         Display assets for a given Tag; Using the Tag Value UUID
  * policies   -->      Scan Policies
  * connectors   -->    Displays information about the Connectors
  * agroup     -->      Displays information about Access Groups
  * status    -->       Displays Tenable.io License and Site information
  * agents    -->       Displays information on Agents
  * webapp    -->       Displays information on Web app Scans
  * tgroup     -->      Displays information about Target Groups
  * licensed    -->     Displays All of your Licensed assets
  * tags       -->      Displays Tag Categories, Values and Value UUID
  * categories -->      Displays Tag Categories and the Category UUID
  * cloud      -->      Displays Cloud assets found in the last 30 days
  * networks    -->     Displays Network IDs
  * version     -->          Displays Current Navi Version
  * usergroup    -->         Display current user groups
    * --membership TEXT -->  Display user of a certain group using the Group ID
  * audits  -->         Display Completed Audits
    * --name TEXT --> Display assets with compliance results for a given Audit file name
    * --uuid TEXT --> Display all compliance findings for the given UUID
  
### Examples
    navi display scanners

    navi display running

    navi display nnm
    
    navi display usergroup --membership 192939
    
    navi display audits --name CIS_CentOS_7_Server_L1_v3.0.0.audit --uuid 1a955d70-468e-4667-b558-e7559c5cec54
    
    navi display audits
    
    navi display audits --uuid 1a955d70-468e-4667-b558-e7559c5cec54

### Add assets manually or via a CSV file - 'add'
To add an asset you need an IP address; Everything else is optional.
If you are going to use a CSV file you need to structure it in this order: IP, Mac, Hostname, FQDN.
This is the order the information is parsed so getting it incorrect will cause errors.

   * --ip TEXT    -->    IP address(s) of new asset
   * --mac TEXT   -->    Mac Address of new asset
   * --netbios TEXT -->  NetBios of new asset
   * --fqdn TEXT  -->    FQDN of new asset
   * --hostname TEXT --> Hostname of new asset
   * --list - TEXT  -->  Import all assets in the CSV file
   * --source - TEXT --> Add the Source

### add examples

    navi add --ip "192.168.1.1" --mac "01:02:03:04:05:06" --netbios "Netbios Name" --fqdn "myfqdn@domain.local" --hostname "myhostname" --source "commandline"
    
    navi add --file my_csv_file.csv --source "My source"

## Add, Disable or Enable Users - 'user'
  * add       -->             Add User. Requires:
    * --username, --u TEXT    Username Required
    * --password, --p TEXT    Users password. Required
    * --permission, --m TEXT  Users Permission. Required
    * --name, --n TEXT        Users Name. Required
    * --email, --e TEXT       Users email. Required
  * enable TEXT   -->        Enable user by User ID
  * disable TEXT    -->      Disable user by User ID

### user examples
Notice - The '\\' before the '!' is to treat '!' as a string and instead of a special command.  
Be careful about certain special characters and their commandline implications.  
Don't share the password with the user, force them to reset their password!

    navi user add --username "thor@marvel.avengers" --password "Dietcoke\!12345" --permission 64 --name "Thor" --email "thor@gmail.com"
    
    navi user enable 192939
    
    navi user disable 192939

## Create a group or Add/Remove a user from a group -  'usergroup'
  * create         Create a new User Group
    * --name TEXT  The Name of the user group. Required
  * add         Add a user to a user group
    * --name TEXT  The Name of the group. Required
    * --user TEXT  The User Name to be added. Required
  * remove      Remove a user from a group. Requires --name and user
    * --name TEXT  The Name of the group. Required
    * --user TEXT  The User Name to be removed. Required

### usergroup examples

    navi usergroup create --name Linux
    
    navi usergroup add --user thor@marvel.avengers --name Linux
    
    navi usergroup remove --user thor@marvel.avengers --name Linux

## Tag assets by Plugin Name, or Plugin ID - 'tag'
Tagging is a key component of a Risk Based vulnerability management program.  Using navi
you can automate tagging based on plugin information or even an existing tag.
Furthermore, you can continue to add to tags to create a nested tag structure.
This tagging functionality and use cases are beyond the scope of this documentation.

   * --c -->         Create a Tag with this Category - Required
   * --v -->         Create a Tag with this Value - Required
   * --d -->         Create a description for your Tag - Optional (TEXT"
   * --plugin -->    Define a Tag by a plugin ID - Optional (TEXT)
   * --name -->      Define a tag by text found in a plugin Name - Optional (TEXT)
   * --group -->     Define a tag by a Agent Group Name - Optional (TEXT)
   * --output TEXT -->  Create a Tag based on the text in the output. Requires --plugin
   * --port TEXT   -->  Create a Tag based on Assets that have a port open
   * --file TEXT -->    Create a Tag based on IPs in a CSV file
   * --scantime TEXT --> Create a Tag for assets that took longer than supplied minutes
   * --cc TEXT   -->     Add a Tag to a new parent tag: Child Category
   * --cv TEXT   -->     Add a Tag to a new parent tag: Child Value
   * --scanid TEXT -->  Create a tag based on a scan ID
   
### tag Examples
    navi tag --c "My Category" --v "My Value" --d "My description" --plugin 93561
    
    navi tag --c "Application Vulns" --v "Java vulns" --name java
    
    navi tag --c "Agent Group" --v "Linux Agents" --group "Linux"

    navi tag --c "Corp Agents" --v "Agent Groups" --cc "Agent Group" --cv "Linux Agents"
    
    navi tag --c "Business Unit A" --v "Daily Scan - Prod" --scanid 1234


### Note on Tagging assets
If you created a new Tag you will need to run an update on the assets to download the new Tag relationships.
This is especially important if you want to export using your newly created tag.

    navi update assets

### Note on Tagging
There were a few limitations to tagging in releases prior to 6.4.14.  All known tagging limitations have been removed


### Migrate - Migrate AWS tags to Tenable.io
As you know Tags are kind of a thing in the cloud and using them in T.io enriches the VM data and makes managing VM workloads easier.  Navi integrates with AWS via the Boto3 python SDK.
Currently, you authenticate via the command-line and as such should be used in Container workloads to reduce any security implications.  In the near future, an AWS keys table will be crated to hold
all of your AWS keys. Using this command takes all of your AWS tags and migrates them to T.io.

* --region  --> "Enter your region Ex: us-west-1"
* --a  --> "Enter your AWS access Key"
* --s  --> "Enter your AWS secret Key"

### Migrate Examples:

    navi migrate --region "us-west-1" --a <AWS ACCESS KEY> --s <AWS SECRET KEY>

## Create Access Groups by Tags or Agent Groups - 'agroup'
Grouping is the theme when trying to influence positive change in a risk
based vulnerability management program.  Since Tagging is the natural
way to group assets, it only makes since to add those to access groups for
limiting access or keeping remediatiors in their lane.

   * --name TEXT       Create an Access group with the following Name
   * -tag              Create a Access Group by a Tag
   * --c TEXT          Category name to use: requires --v and Value Name
   * --v TEXT          Tag Value to use; requires --c and Category Name
   * --group TEXT      Create a Access Group based on a Agent Group
   * --user TEXT       User you want to Assign to the Access Group
   * --usergroup TEXT  User Group you want to assign to the Access Group
   * -scan             Set Scan ONLY permission
   * -view             Set View ONLY permission
   * -scanview         Set Scan AND View permissions

### agroup examples

    navi agroup --name "My New Group" -tag --c "OS" --v "Linux" --user username@yourdomain -scanview
    
    navi agroup --name "My Other Group" --group "Linux" --usergroup "Linux Admins" -scan

## Create Target Groups by Cloud Connector or IPs - 'tgroup'
Target groups are an additional way to scan a group of assets.  However,
it is challenging to scan assets automatically when they are extremely
dynamic or short lived.  For instance, what if you wanted to automate a
non-credentialed scan on the external interface and an authenticated
scan on the internal interface of a cloud asset?

* --name         Create Target Group with the following Name
* --ip           Create Target Group by Ip(s) or subnet(s) separated by coma
* -aws           Turn AWS assets found by the connector into a Target Group
* -gcp           Turn GCP assets found by the connector into a Target Group
* -azure         Turn Azure assets found by the connector into a Target Group
* --days         Set the number of days(30 default) for the IPs found by the connector. Requires: aws, gcp, or azure

### Examples

    navi tgroup --name "By IP" --ip "192.168.128.0/24, 192.168.56.1"
    
    navi tgroup --name "AWS Assets Found in 7 days" -aws --days 7
    
    navi tgroup --name "AWS Assets Privte IPs" -aws -priv
    
    navi tgroup --name "AWS Assets Public IPs" -aws -pub


## Bulk Adjust ACRs based on a Tag - 'lumin'
Adjusting Asset Criticality using context is a key component of a risk based
vulnerability management program.  Since Tagging is the foundation of grouping
assets, it makes since to use these groupings to apply Asset criticality.

   * --acr -->            The new ACR value (1-10)
   * --c -->              The Tag Category to use
   * --v -->              The Tag value to use
   * --note -->           Justification for ACR change
   * -business', '-b'     Add Business Critical To ACR Change Reason(s)")
   * -compliance', '-c'   Add Compliance To ACR Change Reason(s)")
   * -mitigation', '-m'   Add Mitigation Controls To ACR Change Reason(s)")
   * -development', '-d'  Add Development To ACR Change Reason(s)")

   
### Note - ACR Exceptions?
    Tag your assets with "NO:UPDATE" if you don't want to be affected by bulk ACR changes
    Category = NO
    Value = UPDATE
   
### ACR examples
    navi lumin --acr 10 --c "Applications" --v "Core Business" --note "Main application"
    
    navi lumin --acr 9 --c "Corporate Apps" --v "Jira" -d 
    
    navi lumin --acr 8 --c "Corporate Apps" --v "Confluence" -development -b -c


### WAS V2 API - Interact with 2.0 APIs
   * scans -->    Displays WAS Scans
   * start -->   Start Scan with Provided Scan ID
   * details -->      Get Scan Details with Provided Scan ID
   * scan -->    Create a scan via FQDN or CSV file name; use -file option for bulk scan creation via CSV file
   * -file -->     File name of the CSV containing Web Apps for bulk scan creation
   * configs -->  Show config UUIDs to start or stop scans
   * stats -->   Show scan stats
   * summary -->  Summary of all of the Web Apps
   * export --> Export Web app information into a CSV
     * -d --> Export most plugin information per completed web app scan
     * -s --> Export summary information per complted web app scan
   
    navi was scans
    
    navi was configs
    
    navi was details 123456789-aedd-45dc-9c0d-fc87a9a5a1c9
    
    navi was scan http://myscan.com
    
    navi was scan mycsvfile.csv -file
    
    navi was stats 123456789-aedd-45dc-9c0d-fc87a9a5a1c9  
    
    navi export -d
    
    navi export -s
   
### Export Asset, Agent, Consec, or Webapp Data - 'export'

   * assets -->   Export Assets data into CSV: IP, Hostname, FQDN, UUID, exposure, etc
   * agents -->   Export Asset data into CSV: IP, Last Connect, Last scanned, Status
   * was -->      Export Webapp Scan Summary into a CSV - WAS V2
   * consec -->   Export Container Security summary info into a CSV.
   * licensed --> Export a List of all Licensed Assets into a CSV.
   * lumin -->    Export all Asset data including ACR and AES into a CSV. This will take some time
   * network --> Export all Assets of a given network
   * bytag     Export all assets by tag; Include ACR and AES into a CSV
     * --c TEXT   Export bytag with the following Category name
     * --v TEXT   Export bytag with the Tag Value; requires --c and Category Name
     * --ec TEXT  Exclude tag from export with Tag Category; requires --ev
     * --ev TEXT  Exclude tag from export with Tag Value; requires --ec
   * users --> Export User information
   * compliance --> Export Compliance information into a CSV
     * --name TEXT --> Export Compliance data by the Audit file name.  Use navi display audits to get the exact name
     * --uuid TEXT --> Export All compliance data for a given UUID.  Use navi display assets to get an asset uuid
   
### export examples

    navi export assets
    
    navi export agents 
    
    navi export network 00000000-0000-0000-0000-000000000000
    
    navi export compliance
    
    navi export compliance --uuid 1a955d70-468e-4667-b558-e7559c5cec54
    
    navi export compliance --name CIS_CentOS_7_Server_L1_v3.0.0.audit
    
    navi export compliance --name CIS_CentOS_7_Server_L1_v3.0.0.audit --uuid 1a955d70-468e-4667-b558-e7559c5cec54

Export into a CSV, but include the ACR and AES of each asset.  This takes a bit of time.
    
    navi export lumin
    
Export into a CSV via a Tag
    
    navi export bytag --c "OS" --v "Linux"

Export into a CSV via a Tag; but exclude a specific Tag.

    navi export bytag --c "OS" --v "Linux" --ec "OS" --ev "AWS"

## Delete an Object by an ID

  * agroup   -->   Delete an access group by UUID
  * asset   -->    Delete an Asset by Asset UUID
  * bytag   -->    Delete assets by Tag. Supply Tag-string: Category:value EX: OS:Linux
  * category  -->  Delete Tag Category by Category UUID
  * container -->  Delete a container by '/repository/image/tag'
  * policy  -->    Delete a Policy by Policy ID
  * repository --> Delete repository from Container Security
  * scan    -->    Delete a Scan by Scan ID
  * tgroup  -->    Delete a target-group by target-group ID
  * user   -->     Delete a user by User ID - Not UUID
  * usergroup -->  Delete a user group by the Group ID
  * value   -->    Delete Tag Value by Value UUID

### delete examples

    navi delete 1234 -scan

    navi delete 4567 -agroup

    navi delete 8910 -tgroup

    navi delete 12345 -asset

    navi delete 6789 -policy
    
    navi delete bytag OS:linux 


### Mail a Report
* -latest -      Mail a report of the latest scan: Same output as "report -latest"
* -consec -      Mail a report of the ConSec Summary: Same output as "list -containers"
* -webapp -      Mail a report of the WebApp Summary
* --message -    Email a custom message for automation. Concatinate a navi command.
* --to -         Email address to send to
* --subject -    Subject of the email
* -v -           Display a copy of the message on screen

### mail examples

    navi mail --latest --to "your@email.com" --subject "This is my subject line" 

Send a Special note to support automation

    navi mail --to "your@email.com" --subject "navi automation note" --message "Download Finished"

Send the output of a Navi command using --message

    navi mail --to "your@email.com" --subject "WAS Report" --message "`navi was --sd 35b54d95-f1b5-40f1-a98e-4f4c82a2a719`"

## Scan Commands
  * change   Change Ownership
  * create   Quickly Scan a Target
  * details  Display Scan Details
  * hosts    Display Hosts found by a scan
  * latest   Display the Latest scan information
  * pause    Pause a running Scan
  * resume   Resume a paused Scan
  * start    Start a valid Scan
  * status   Get Scan Status
  * stop     Stop a Running Scan

### Change Scanner Ownership

First See what scans a user owns

    navi scan change --who "admin@your.login"

Then tansfer the scans owned by User A to User B

    navi scan change --owner "userA@your.login" --new "userB@your.login"


### Create a Scan
* --plugin - Plugin required for Remediation Scan")
* --cred - UUID of your intended credentials")
* -discovery - Scan using the Discovery Template")
* --custom - Scan using a custom Scan Template")
* --scanner - help="Scanner ID")

### Examples

    navi scan create 192.168.128.1 -scanner 123456
    
    navi scan create 192.168.128.0/24 -discovery
    
    navi scan create 192.168.128.2 -scanner <scanner id> --cred <cred uuid> --plugin <plugin>

### Workflow
  * A basic Policy is used by default. Use -discovery or -custom alter
  * If -scanner option is missing you will be prompted to enter in your scanner ID after displaying your scanners
  * Scan will immediately kick off

### Control your scans
    navi scan pause 13

    navi scan resume 13

    navi scan stop 13

    navi scan start 13

### Find Available scanners
    navi display -scanners

### Find details of a certain scan

    navi scan details 13

### Create 100s of Webapp Scans from a CSV File
To Receive a file for Navi to use you must push the file to the container.  
Netcat is installed on the container to do this, or you can use the 'listen'  
command to accomplish this.
  
    navi was scan <your_csv_file.csv> -file
    
    
* Choose your Scan type : Webapp Overview/Webapp Scan/SSL Scan/Config Scan
* Choose your scanner: A list will be displayed
* Choose The Owner of your Scan: A list of owners will be displayed
* Scans will be created but not started.

### Getting Data into the Docker Container

From the container - Prepare your container to receive a file

    navi listen

    or

    nc -l -p 8000 > yourfilename.csv

From the computer with the file - Send the file

    nc containerhostIP 8000 < yourfilename.csv


