# Navi Pro - The Tenable.io Swiss Army Knife
A command-line tool which leverages the Tenable.io API to reduce the time it takes to get information that is common 
in Cyber Exposure or Vulnerability Management. 

    *** This tool is not an officially supported Tenable project ***
    
    *** Use of this tool is subject to the terms and conditions identified below,
     and is not subject to any license agreement you may have with Tenable ***

### Important Notes
Navi Pro will download the entire data-set(90 days) locally after API keys are 
entered and the update command is used! To download Vuln and Asset data you have to be an Administrator in Tenable.io.

All Vulns and All Assets are downloaded into a SQLLITE database named navi.db in the current directory.
 
 Most of the API calls nessessary to make navi work require access to
 your all of the available data.  Tenable.io has a 5000 record limit so Navi Pro utilizes the Export API.
 
 The data will not be updated until you run the update command.  Keep this in mind when adding elements to Tenable.io like Tags.
 
    navi update
    
 Alternatively you can select which export you want to update:
 
    navi update -assets
    
    navi update -vulns
 
 Furthermore, you can limit how much data is downloaded by using the --days command
 
    navi update -assets --days 2
 
 You can even specify your export id.
 
    navi update -vulns --exid 123456-987654-asdfgh-jklopi-ididis
    
 You can also control the amount of threads used for downlaods (1-10)
 The Default thread value is 10.
 
    navi update -vulns --threads 4
 
### My container keeps getting "Killed"
To speed up downloads navi uses threading. It pulls 500 asset chunks on 10 threads and since the vulnerabilities per asset
fluctuate this can spike the memory above 2G.  If this happens increase your memeory to 4G.

[Directions for Mac](https://docs.docker.com/docker-for-mac/#memory)

[Directions for Windows](https://docs.docker.com/docker-for-windows/#advanced)
 
### I keep getting DB locks
I'm still working on a fix for large accounts, those over 100K assets.  For now use the thread option to avoid DB locks by reducing it to 1.

    navi update --threads 1
 
### What is my Navi Version
Versions older than 5.1.36 do not have this feature.

    navi display -version

### Are my Keys inputted correctly?
In different terminals it can be a challenge to copy the keys to navi since you can not be sure it copied correctly.  

Use the below commands to check your keys
    
    navi find --query "select * from keys;"

Alternatively, you could try entering your keys again using the '-clear' command to see what is being copied to the screen.

    navi keys -clear

### What is the biggest Tenable.io instance Navi has been tested on?
Navi 5.1.4 was recently tested on a container with 100,000 assets and 13 million vulnerabilties.  
It took 30 mins for t.io to prepare the download and 30 mins to download and parse the data
 into navi.db.  On another internet connection the entire process too 2.5 hours.
    

# Download and Configure navi in a Docker Container

    docker pull silentninja/navi:latest
  
    docker run -it -p 8000:8000 silentninja/navi:latest /bin/bash 

    navi keys
    
    navi update
  
## Detach from Container
    CTR+Q+P - CTR+Q+P

## Attach to Contianer
    docker attach <container id>
  
    <press enter>

## Configure Container For Reporting
Navi has a few reporting capabilities where a CSV is the output.  To extract this data from the container you will need to launch the container with port 8000 exposed and use the 'http' command to extract the reports.

    docker run -it -p 8000:8000 silentninja/navi:latest /bin/bash

### Extract Data from the Container
To extract data from the container you need to run an http server.  Use the below built in command.

    navi http

 * Navigate to the website: http://127.0.0.1:8000
 * Simply download the item you want by clicking on it.
 
# Download Navi Pro from PyPI - 
## Prepare your Machine
 * Install [Python3](https://realpython.com/installing-python/)
 
## Install Navi Pro using pip

    pip3 install navi-pro

## Uninstall Navi Pro using pip

    pip3 uninstall navi-pro

# Navi General Usage
Before you begin you need the Keys! The program will continue to error out without valid API keys.
Note: The keys will not show up on the screen; similar to a password prompt.

    navi keys

Alternatively, to support automation, you can add your keys with a single command

    navi keys --a your-access-key  --s your-secret-key

Each command has two parts: the Command and the Option/Request. Double-Dash(--) commands expect a text value. Single-Dash commands do not have an expected input.  

There are eighteen core commands:
 * api - query api endpoints
 * ip - find details on Specific IPs
 * find - Find information: credential failures, containers, etc
 * report - Report on Information: Latest scan information, Container vulns
 * display - List details: users, logs, navi version, etc
 * group - Create Target groups based off of Plugin ID, Plugin Name or Plugin Output
 * export - Export Agent or Asset data into a CSV
 * delete - Delete an object by it's ID
 * mail - Mail a report 
 * tag - Create a Category/Value Pair
 * lumin - Bulk adjust ACRs based on a tag
 * add - Manually Add an asset to Tenable.io or a list of assets via CSV
 * delete - Delete a scan by Scan ID
 * agroup - Create an Access Group by Tag or Agent Group
 * was - Interact with the WAS 2.0 V2 API
 * change - Change Scan Ownership
 * user - Add, enable or disable a user
 * usergroup - Create a new group and Add or remove users from a group

 
 There are twelve single use commands:
 * scan - Create and launch a scan
 * start - Start a scan by Scan-ID
 * pause - Pause a scan by Scan-ID
 * resume - Resume a scan by Scan-ID
 * stop - Stop a scan by Scan-ID
 * update - Update local Export Vuln and Asset data.
 * status - Get the latest status by Scan ID
 * mac - Get the manufacture by Mac Address
 * keys - Add or update your keys
 * http - Run an http server to extract files from the container
 * listen - Run a netcat listener to receive a single file
 * smtp - Enter or update your SMTP information
 
 

### Explore the Tenable.io API - 'api'
  Enter in a API endpoint and get a pretty print json ouput.  Try some of the below endpoints:
   * /scans
   * /scanners
   * /users

### Examples

    navi api /scans

    navi api /scanners
  
### IP address queries - 'ip'
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

### Examples

    navi ip 192.168.1.1 --plugin 19506

    navi ip 192.168.1.1 -details -software

### Find information - 'find'
  * --plugin TEXT --> Find Assets where this plugin fired
  * -docker -->       Find Running Docker Containers
  * -webapp -->       Find Web Servers running
  * -creds  -->       Find Credential failures
  * --scantime TEXT -->   Find Assets where the scan duration is over X mins
  * -ghost -->        Find Assets found by a Connector and not scanned by Nessus(AWS ONLY)
  * --port TEXT --->  Find assets with an the open port provided
  * --query TEXT ---> Query the db directly and display the output
  * --output TEXT --> Find Assets based on the text in the output. Requires --plugin
  * --name TEXT --->  Find Assets based on Text in a plugin Name

### Examples

    navi find --plugin 19506
    
    navi find -docker

    navi find --time 10
    
    navi find --query "select * from assets;"
    
    navi find --plugin 20869 --output "splunk"
    
    navi find --name java
    
    navi find --port 8080

### Reports - Information - 'report'
  * -latest -->          Report the Last Scan Details
  * --container TEXT --> Report Vulns of CVSS 7 or above by Container ID.
  * --docker TEXT -->    Report Vulns of CVSS 7 or above by Docker ID
  * --comply TEXT -->    Check to see if your container complies with your Policy
  * --details TEXT -->   Report Scan Details including Vulnerability Counts by Scan ID
  * --summary TEXT -->   Report Scan Summary by Scan ID
  * --network TEXT -->   Report Assets of a given Network

### Examples
    navi report -latest

    navi report --container 48b5124b2768

    navi report --docker 48b5124b2768

    navi report --comply 48b5124b2768

    navi report --summary 13

### Display - Common Information - 'display'
  * -scanners -->   List all of the Scanners
  * -users -->      List all of the Users
  * -exclusions --> List all Exclusions
  * -containers --> List all containers and their Vulnerability  Scores
  * -logs -->       List The actor and the action in the log file
  * -running -->    List the running Scans
  * -scans -->      List all Scans
  * -nnm -->        Nessus Network Monitor assets and their vulnerability scores
  * -assets -->     Assets found in the last 30 days
  * -policies -->   Scan Policies
  * -connectors --> Displays information about the Connectors
  * -agroup -->     Displays information about Access Groups
  * -status -->     Displays Tenable.io License and Site information
  * -agents -->     Displays information on Agents
  * -webapp -->     Displays information on Web app Scans
  * -tgroup -->     Displays information about Target Groups
  * -licensed -->   Displays All of your Licensed assets
  * -tags -->       Displays Tag Categories, Values and Value UUID
  * -categories --> Displays Tag Categories and the Category UUID
  * -cloud -->      Displays Cloud assets found in the last 30 days
  * -networks -->   Displays Network IDs
  * -version -->    Displays Current Navi Version
  * -usergroup -->  Display current user groups
  * --membership -> Display user of a certain group using the Group ID
  
### Examples
    navi display -scanners

    navi display -running

    navi display -nnm
    
    navi display --membership 192939

### Add assets manually or via a CSV file - 'add'
To add an asset you need an IP address; Everything else is optional.
If you are going to use a CSV file you need to structure it in this order: IP, Mac, Hostname, FQDN.
This is the order the information is parsed so getting it incorrect will cause errors.

   * --ip TEXT        IP address(s) of new asset
   * --mac TEXT       Mac Address of new asset
   * --netbios TEXT   NetBios of new asset
   * --fqdn TEXT      FQDN of new asset
   * --hostname TEXT  Hostname of new asset
   * --list - TEXT    Import all assets in the CSV file
   * --source - TEXT  Add the Source

### Examples

    navi add --ip "192.168.1.1" --mac "01:02:03:04:05:06" --netbios "Netbios Name" --fqdn "myfqdn@domain.local" --hostname "myhostname" --source "commandline"
    
    navi add --file my_csv_file.csv --source "My source"

### Add, Disable or Enable Users - 'user'
  * -add                    Add User. Requires:
  * --username, --u TEXT    Username. Requires: -add, -enable, or -disable
  * --password, --p TEXT    Users password. Requires: -add
  * --permission, --m TEXT  Users Permission. Requires: -add
  * --name, --n TEXT        Users Name. Requires: -add
  * --email, --e TEXT       Users email. Requires: -add
  * --enable TEXT           Enable user by User ID
  * --disable TEXT          Disable user by User ID

### Examples
Notice - The '\\' before the '!' is to treat '!' as a string and as a special command.  Becareful about certain special charaters and their commandline implications.  Don't share this password with the user.  Force them to reset their password!

    navi user -add --username "thor@marvel.avengers" --password "Dietcoke\!12345" --permission 64 --name "Thor" --email "thor@gmail.com"
    
    navi user --enable 192939
    
    navi user --disable 192939

### Create a group or Add/Remove a user from a group -  'usergroup'
  * -new         Create a new Group. Required: --name
  * -add         Add a user to a group. Required: --user and --name
  * --name TEXT  The Name of the group
  * --user TEXT  The User Name to be added or removed
  * -remove      Remove a user from a group. Requires --name and user

### Examples

    navi usergroup -new Linux
    
    navi usergroup -add --user thor@marvel.avengers --name Linux

### Tag assets by Plugin Name, or Plugin ID - 'tag'
   * --c -->         Create a Tag with this Category - Required
   * --v -->         Create a Tag with this Value - Required
   * --d -->         Create a description for your Tag - Optional (TEXT"
   * --plugin -->    Define a Tag by a plugin ID - Optional (TEXT)
   * --name -->      Define a tag by text found in a plugin Name - Optional (TEXT)
   * --group -->     Define a tag by a Agent Group Name - Optional (TEXT)
   * --output TEXT   Create a Tag based on the text in the output. Requires --plugin
   * --port TEXT     Create a Tag based on Assets that have a port open
   * --file TEXT     Create a Tag based on IPs in a CSV file
   * --scantime TEXT Create a Tag for assets that took longer than supplied minutes

   
### Examples
    navi tag --c "My Category" --v "My Value" --d "My description" --plugin 93561
    navi tag --c "Application Vulns" --v "Java vulns" --name java
    navi tag --c "Agent Group" --v "Linux Agents" --group "Linux"

### Note on Tagging assets
If you created a new Tag you will need to run an update on the assets to download the new Tag relationships.
This is especially important if you want to export using your newly created tag.

    navi update -assets
 
### Create Access Groups by Tags or Agent Groups - 'agroup'
   * --name TEXT   Create an Access group with the following Name
   * -tag          Create a Access Group by a Tag
   * --c TEXT      Category name to use
   * --v TEXT      Tag Value to use; requires --c and Category Name
   * --group TEXT  Create a Tag based on a Agent Group
   * --user TEXT   User you want to Assign to the Access Group")
   * --usergroup   User Group you want to assign to the Access Group")
   * -scan         Set Scan ONLY permission")
   * -view         Set View ONLY permission")
   * -scanview     Set Scan AND View permissions")

### Examples

    navi agroup --name "My New Group" -tag --c "OS" --v "Linux" --user username@yourdomain -scanview
    
    navi agroup --name "My Other Group" --group "Linux" --usergroup "Linux Admins" -scan
    
### Bulk Adjust ACRs based on a Tag - 'lumin'
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
   
### Examples
    navi lumin --acr 10 --c "Applications" --v "Core Business" --note "Main application"
    
    navi lumin --acr 9 --c "Corporate Apps" --v "Jira" -d 
    
    navi lumin --acr 8 --c "Corporate Apps" --v "Confluence" -development -b -c


### WAS V2 API - Interact with 2.0 APIs
   * -scans -->    Displays WAS Scans
   * --start -->   Start Scan with Provided Scan ID
   * --sd -->      Get Scan Details with Provided Scan ID
   * --scan -->    Create a scan via FQDN or CSV file name; use -file option for bulk scan creation via CSV file
   * -file -->     File name of the CSV containing Web Apps for bulk scan creation
   * -configs -->  Show config UUIDs to start or stop scans
   * --stats -->   Show scan stats
   * -summary -->  Summary of all of the Web Apps
   
    navi was -scans
    
    navi was -configs
    
    navi was --sd 123456789-aedd-45dc-9c0d-fc87a9a5a1c9
    
    navi was --scan http://myscan.com
    
    navi was --scan mycsvfile.csv -file
    
    navi was --stats 123456789-aedd-45dc-9c0d-fc87a9a5a1c9  
   
### Export Asset, Agent, Consec, or Webapp Data - 'export'

   * -assets -->   Export Assets data into CSV: IP, Hostname, FQDN, UUID, exposure, etc
   * -agents -->   Export Asset data into CSV: IP, Last Connect, Last scanned, Status
   * -was -->      Export Webapp Scan Summary into a CSV - WAS V2
   * -consec -->   Export Container Security summary info into a CSV.
   * -licensed --> Export a List of all Licensed Assets into a CSV.
   * -lumin -->    Export all Asset data including ACR and AES into a CSV. This will take some time
   * --network --> Export all Assets of a given network
   * -bytag     Export all assets by tag; Include ACR and AES into a CSV
   * --c TEXT   Export bytag with the following Category name
   * --v TEXT   Export bytag with the Tag Value; requires --c and Category Name
   * --ec TEXT  Exclude tag from export with Tag Category; requires --ev
   * --ev TEXT  Exclude tag from export with Tag Value; requires --ec
   
### Examples

    navi export -assets
    
    navi export -agents -assets -was -consec -licensed
    
    navi export --network 00000000-0000-0000-0000-000000000000

Export into a CSV, but include the ACR and AES of each asset.  This takes a bit of time.
    
    navi export -lumin
    
Export into a CSV via a Tag
    
    navi export -bytag --c "OS" --v "Linux"

Export into a CSV via a Tag; but exclude a specific Tag.

    navi export -bytag --c "OS" --v "Linux" --ec "OS" --ev "AWS"

### Delete an Object by an ID
* -scan -      Delete a scan by ID
* -agroup -    Delete an Access group
* -tgroup -    Delete a Target Group
* -policy -    Delete a Policy
* -asset -     Delete an asset
* -container - Delete a container by container ID
* -value -     Delete a Tag value by Value UUID
* -category -  Delete a Tag category by the Category UUID
* --bytag -    Delete All assets that have a certain tag  - specify Value and tag.category
  * --c        Category Name to be used for delete bytag
  * --v        Value Name to be used for delete bytag
* -user        Delete a user by User ID - API BUG! - Doesn't work right now
* -usergroup   Delete a usergroup by Group ID

### Examples

    navi delete 1234 -scan

    navi delete 4567 -agroup

    navi delete 8910 -tgroup

    navi delete 12345 -asset

    navi delete 6789 -policy
    
    navi delete Linux --bytag tag.OS

### Mail a Report
* -latest -      Mail a report of the latest scan: Same output as "report -latest"
* -consec -      Mail a report of the ConSec Summary: Same output as "list -containers"
* -webapp -      Mail a report of the WebApp Summary
* --message -    Email a custom message for automation. Concatinate a navi command.
* --to -         Email address to send to
* --subject -    Subject of the email
* -v -           Display a copy of the message on screen

### Examples

    navi mail --latest --to "your@email.com" --subject "This is my subject line" 

Send a Special note to support automation

    navi mail --to "your@email.com" --subject "navi automation note" --message "Download Finished"

Send the output of a Navi command using --message

    navi mail --to "your@email.com" --subject "WAS Report" --message "`navi was --sd 35b54d95-f1b5-40f1-a98e-4f4c82a2a719`"



### Change Scanner Ownership

First See what scans a user owns

    navi change --who "admin@your.login"

Then tansfer the scans owned by User A to User B

    navi change --owner "userA@your.login" --new "userB@your.login"
    
## Use Cases

### What was last scanned?
    navi report -latest

### What scans are running right now?
    navi display -running

### Find a Scan id by Scan Name
    navi display -scan | grep -b2 <ScanName>

### Create a Scan
    navi scan 192.168.128.1
    
    navi scan 192.168.128.0/24
    
  * Choose your scan type: Basic or Discovery
  * Pick your scanner by ID: scanners will be displayed
  * Scan will immediately kick off

### Control your scans
    navi pause 13

    navi resume 13

    navi stop 13

    navi start 13

### Find Available scanners
    navi display -scanners

### Create 100s of Webapp Scans from a CSV File
To Receive a file for Navi Pro to use you must push the file to the container.  Netcat is installed on the container to do this, or you can use the 'listen' command to accomplish this.
  
    navi was --scan <your_csv_file.csv> -file
    
    
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


