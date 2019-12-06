# Navi Pro - The Tenable.io Swiss Army Knife
A command-line tool which leverages the Tenable.io API to reduce the time it takes to get information that is common 
in Cyber Exposure or Vulnerability Management. *** This is not Supported by Tenable ***

### Important Note
Navi Pro will download the entire data-set(90 days) locally after API keys are 
entered and the update command is used! To download Vuln and Asset data you have to be an Administrator in Tenable.io.

All Vulns and All Assets are downloaded into a SQLLITE database named navi.db.  
 
 Most of the API calls nessessary to make Navi work require access to
 your all of the available data.  Tenable.io has a 5000 record limit so Navi_pro.py utilizes the Export API.
 
 The data will not be updated until you run the update command.  Keep this in mind when adding elements to Tenable.io like Tags.
 
    Navi update
    
 Alternatively you can select which export you want to update:
 
    Navi update -assets
    
    Navi update -vulns
 
 Furthermore, you can limit how much data is downloaded by using the --days command
 
    Navi update -assets --days 2
 
## Download and Configure Navi in a Docker Container

    docker pull silentninja/navi
  
    docker run -it -p 8000:8000 silentninja/navi:latest /bin/bash 

    Navi keys
    
    Navi update
  
## Detach from Container
    CTR+Q+P - CTR+Q+P

## Attach to Contianer
    docker attach <container id>
  
    <press enter>

## Configure For Reporting
Navi has a few reporting capabilities where a CSV is the output.  To extract this data from the container you will need to launch the container with port 8000 exposed and use the 'http' command to extract the reports.

    docker run -it -p 8000:8000 silentninja/navi:latest /bin/bash

### Extract Data
To extract data from the container you need to run an http server.  Use the below built in command.

    Navi http

 * Navigate to the website: http://0.0.0.0:8000
 * Simply download the item you want by clicking on it.

## Usage
Before you begin you need the Keys! The program will continue to error out without valid API keys

    Navi keys

Each command has two parts: the Command and the Option/Request. Double-Dash(--), commands expect a text value. Single-Dash commands do not have an expected input.  

There are thirteen core commands: 
 * api - query api endpoints
 * ip - find details on Specific IPs
 * find - Find information: credential failures, containers, etc
 * report - Report on Information: Latest scan information, Container vulns
 * list - List details: users, logs, etc
 * group - Create Target groups based off of Plugin ID, Plugin Name or Plugin Output
 * export - Export Agent or Asset data into a CSV
 * delete - Delete an object by it's ID
 * mail - Mail a report 
 * tag - Create a Category/Value Pair
 * lumin - Bulk adjust ACRs based on a tag
 * add - Manually Add an asset to Tenable.io or a list of assets via CSV
 * delete - Delete a scan by Scan ID
 * agroup - Create an Access Group by Tag or Agent Group
 
 There are thirteen single use commands: 
 * scan - Create and launch a scan
 * start - Start a scan by Scan-ID
 * pause - Pause a scan by Scan-ID
 * resume - Resume a scan by Scan-ID
 * stop - Stop a scan by Scan-ID
 * spider - Create a WebApp scan for every URL in a CSV
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

    Navi api /scans

    Navi api /scanners
  
### IP address queries - 'ip'
  * --plugin TEXT --> Find Details on a particular plugin ID
  * -n -->            Netstat Established and Listening and Open Ports
  * -p -->            Patch Information
  * -t -->            Trace Route
  * -o -->            Process Information
  * -c -->            Connection Information
  * -s -->            Services Running
  * -r -->            Local Firewall Rules
  * -d -->            Scan Detail: 19506 plugin output
  * -patches -->      Missing Patches
  * -software -->     Find software installed on Unix of windows hosts
  * -outbound -->     Display outbound connections found by NNM
  * -exploit -->      Display exploitable vulnerabilities
  * -critical -->     Display critical vulnerabilities
  * -details -->      Details on an Asset: IP, UUID, Vulns, etc

### Examples

    Navi ip 192.168.1.1 --plugin 19506

    Navi ip 192.168.1.1 -details -software

### Find information - 'find'
  * --plugin TEXT --> Find Assets where this plugin fired
  * -docker -->       Find Running Docker Containers
  * -webapp -->       Find Web Servers running
  * -creds  -->       Find Credential failures
  * --time TEXT -->   Find Assets where the scan duration is over X mins
  * -ghost -->        Find Assets found by a Connector and not scanned by Nessus(AWS ONLY)

### Examples


    Navi find --plugin 19506
    
    Navi find -docker

    Navi find --time 10

### Reports - Information - 'report'
  * -latest -->          Report the Last Scan Details
  * --container TEXT --> Report Vulns of CVSS 7 or above by Container ID.
  * --docker TEXT -->    Report Vulns of CVSS 7 or above by Docker ID
  * --comply TEXT -->    Check to see if your container complies with your Policy
  * --details TEXT -->   Report Scan Details including Vulnerability Counts by Scan ID
  * --summary TEXT -->   Report Scan Summary by Scan ID

### Examples
    Navi report -latest

    Navi report --container 48b5124b2768

    Navi report --docker 48b5124b2768

    Navi report --comply 48b5124b2768

    Navi report --summary 13

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
  
### Examples
    Navi display -scanners

    Navi display -running

    Navi display -nnm

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
   
### Tag assets by Plugin Name, or Plugin ID - 'tag'
   * --c -->      Create a Tag with this Category - Required
   * --v -->      Create a Tag with this Value - Required
   * --d -->      Create a description for your Tag - Optional (TEXT"
   * --plugin --> Define a Tag by a plugin ID - Optional (TEXT)
   * --name -->   Define a tag by text found in a plugin Name - Optional (TEXT)
   * --group -->  Define a tag by a Agent Group Name - Optional (TEXT)
   * --output TEXT  Create a Tag based on the text in the output. Requires --plugin

   
### Examples
    Navi tag --c "My Category" --v "My Value" --d "My description" --plugin 93561
    Navi tag --c "Application Vulns" --v "Java vulns" --name java
    Navi tag --c "Agent Group" --v "Linux Agents" --group "Linux"


### Create Access Groups by Tags or Agent Groups - 'agroup'
   * --name TEXT   Create an Access group with the following Name
   * -tag          Create a Access Group by a Tag
   * --c TEXT      Category name to use
   * --v TEXT      Tag Value to use; requires --c and Category Name
   * --group TEXT  Create a Tag based on a Agent Group
   
### Examples

    Navi agroup --name "My New Group" -tag --c "OS" --v "Linux"
    
    Navi agroup --name "My Other Group" --group "Linux
    
### Bulk Adjust ACRs based on a Tag - 'lumin'
   * --acr -->  The new ACR value (1-10)
   * --c -->    The Tag Category to use
   * --v -->    The Tag value to use
   * --note --> Justification for ACR change
   
### Note - ACR Exceptions?
    Tag your assets with "NO:UPDATE" if you don't want to be affected by bulk ACR changes
    Category = NO
    Value = UPDATE
   
### Examples
    Navi lumin --acr 10 --c "Applications" --v "Core Business" --note "Main application"

### Export Asset, Agent, Consec, or Webapp Data - 'export'

   * -assets -->   Export Assets data into CSV: IP, Hostname, FQDN, UUID, exposure, etc
   * -agents -->   Export Asset data into CSV: IP, Last Connect, Last scanned, Status
   * -webapp -->   Export Web applications into a CSV: FQDN, Critical, High, Medium, Low
   * -consec -->   Export Container Security summary info into a CSV.
   * -licensed --> Export a List of all Licensed Assets into a CSV.
   * -lumin     Export all Asset data including ACR and AES into a CSV. This will take some time
   * -bytag     Export all assets by tag; Include ACR and AES into a CSV
   * --c TEXT   Export bytag with the following Category name
   * --v TEXT   Export bytag with the Tag Value; requires --c and Category Name
   * --ec TEXT  Exclude tag from export with Tag Category; requires --ev
   * --ev TEXT  Exclude tag from export with Tag Value; requires --ec
   
### Examples

    Navi export -assets
    
    Navi export -agents -assets -webapp -consec -licensed

### Delete an Object by an ID
* scan -      Delete a scan by ID
* agroup -    Delete an Access group
* tgroup -    Delete a Target Group
* policy -    Delete a Policy
* asset -     Delete an asset
* container - Delete a container by container ID
* tag -       Delete a Tag value by Value UUID
* category -  Delete a Tag category by the Category UUID

### Examples


    Navi delete 1234 -scan

    Navi delete 4567 -agroup

    Navi delete 8910 -tgroup

    Navi delete 12345 -asset

    Navi delete 6789 -policy

### Mail a Report
* latest - Mail a report of the latest scan: Same output as "report -latest"
* consec - Mail a report of the ConSec Summary: Same output as "list -containers"
* webapp - Mail a report of the WebApp Summary


## Use Cases

### What was last scanned?
    Navi report -latest

### What scans are running right now?
    Navi list -running

### Find a Scan id by Scan Name
    Navi list -scan | grep -b2 <ScanName>

### Create a Scan
    Navi.py scan 192.168.128.1
    
    Navi.py scan 192.168.128.0/24
    
  * Choose your scan type: Basic or Discovery
  * Pick your scanner by ID: scanners will be displayed
  * Scan will immediately kick off

### Control your scans
    Navi pause 13

    Navi resume 13

    Navi stop 13

    Navi start 13

### Find Available scanners
    Navi list -scanners

### Create 100s of Webapp Scans from a CSV File
To Receive a file for Navi Pro to use you must push the file to the container.  Netcat is installed on the container to do this, or you can use the 'listen' command to accomplish this.
  
    Navi spider <your_csv_file.csv>
    
    
* Choose your Scan type : Webapp Overview or Webapp Scan
* Choose your scanner: A list will be displayed
* Scans will be created but not started.
* An output of the Webapp URL and Scan ID will be displayed on completion

### Getting Data into the Container

From the container - Prepare your container to receive a file

    Navi listen

    or

    nc -l -p 8000 > yourfilename.csv

From the computer with the file - Send the file

    nc containerhostIP 8000 < yourfilename.csv


