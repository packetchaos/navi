from os import system as sys
import time

# Instructions #
# Replace 'access_key and secrek_key with your keys
# Add/remove or adjust any of the below commands
# The structure is there to help you with the command syntax.

start = time.time()
sys('navi keys --a access_key --s secret_key')

sys('echo Adding User Groups')
# Create User Groups
sys('navi usergroup new --name "Linux" >> user_navi.log')
sys('navi usergroup new --name "Corporate Apps" >> user_navi.log')
sys('navi usergroup new --name "Custom Apps" >> user_navi.log')
sys('navi usergroup new --name "Software" >> user_navi.log')

sys('echo creating users')
# Create or enable users
sys('navi user add --username "thor@marvel.avengers" --password "Dietcoke\!12345" --permission 64 --name "Thor" --email "thor@marvel.avengers" >> user_navi.log' )
sys('navi user add --username "hulk@marvel.avengers" --password "Dietcoke\!12345" --permission 64 --name "Hulk Smash" --email "hulk@marvel.avengers" >> user_navi.log')
sys('navi user add --username "ironman@marvel.avengers" --password "Dietcoke\!12345" --permission 64 --name "IronMan" --email "ironman@@marvel.avengers" >> user_navi.log')
sys('navi user add --username "spiderman@marvel.avengers" --password "Dietcoke\!12345" --permission 64 --name "Spiderman" --email "spiderman@marvel.avengers" >> user_navi.log')
sys('navi user add --username "strange@marvel.avengers" --password "Dietcoke\!12345" --permission 64 --name "Dr Strange" --email "strange@marvel.avengers" >> user_navi.log')

sys('echo Adding users to groups')
# Add a user to a group
sys('navi usergroup add --user "spiderman@test.tenable" --name "Software" >> user_navi.log')
sys('navi usergroup add --user "ironman@test.tenable" --name "Linux" >> user_navi.log')
sys('navi usergroup add --user "hulk@test.tenable" --name "Corporate Apps" >> user_navi.log')
sys('navi usergroup add --user "thor@test.tenable" --name "Custom Apps" >> user_navi.log')
sys('navi usergroup add --user "spiderman@test.tenable" --name "Custom Apps" >> user_navi.log')

sys('echo first update')
# First we need to download all of our data.
sys('navi update >> navi_update.log')

sys('echo Turn Agents into groups')
# Turn Agent Groups into Tags
sys('navi tag --c "Agent Group" --v "Linux" --group "Linux" >> agent_navi.log')
sys('navi tag --c "Agent Group" --v "Windows" --group "Windows" >> agent_navi.log')

sys('echo Tagging by Ports')
# Find open Ports and Tag assets that have them open
sys('navi tag --c "Tenable" --v "Appliance" --port 8000 >> tag_navi.log')
sys('navi tag --c "Corporate Apps" --v "Confluence" --port 8090 >> tag_navi.log')
sys('navi tag --c "Corporate Apps" --v "Jira" --port 8080 >> tag_navi.log')
sys('navi tag --c "Tenable" --v "Nessus Scanner" --port 8834 >> tag_navi.log')
sys('navi tag --c "Tenable" --v "Nessus NNM" --port 8835 >> tag_navi.log')
sys('navi tag --c "Open Ports" --v "Port 80" --port 80 >> tag_navi.log')
sys('navi tag --c "Custom Apps" --v "Crypto Investments" --port 5000 >> tag_navi.log')
sys('navi tag --c "Custom Apps" --v "New host" --port 5001 >> tag_navi.log')
sys('navi tag --c "Custom Apps" --v "Solutions Container" --port 5002 >> tag_navi.log')
sys('navi tag --c "Custom Apps" --v "Lab Status Container" --port 5003 >> tag_navi.log')
sys('navi tag --c "Custom Apps" --v "Water Capture Container" --port 5004 >> tag_navi.log')
sys('navi tag --c "Custom Apps" --v "Water Display Container" --port 5005 >> tag_navi.log')

sys('echo Tagging by Plugins')
# Tag assets where a plugin fired.
sys('navi tag --c "Corporate Apps" --v "Docker hosts" --plugin 93561 >> tag_navi.log')
sys('navi tag --c "VMware" --v "VMware Host" --plugin 20301 >> tag_navi.log')
sys('navi tag --c "Discover" --v "Web Apps" --plugin 1442 >> tag_navi.log')
sys('navi tag --c "Discover" --v "Web Services / SSH Services" --plugin 22964 >> tag_navi.log')
sys('navi tag --c "VMware" --v "Virtual Machine" --plugin 20094 >> tag_navi.log')
sys('navi tag --c "Corporate Apps" --v "Security Center" --plugin 71158 >> tag_navi.log')
sys('navi tag --c "Discover" --v "Unknown OS" --plugin 50350 >> tag_navi.log')
sys('navi tag --c "Firewall" --v "PF Sense" --plugin 106952 >> tag_navi.log')

sys('echo Tagging by Text in Plugin Name')
# Tag assets where Text was found in the plugin Name
sys('navi tag --c "Certificate Issues" --v "Certs" --name "Certificate" >> tag_navi.log')
sys('navi tag --c "Certificate Issues" --v "Expiry" --name "Expiry" >> tag_navi.log')
sys('navi tag --c "Software" --v "Java" --name "java" >> tag_navi.log')
sys('navi tag --c "Software" --v "Adobe" --name "adobe" >> tag_navi.log')

sys('echo Tagging by Text found in the output of a Plugin')
# Tag assets with text found in the output
sys('navi tag --c "Corporate Apps" --v "Splunk" --plugin 22869 --output "splunk" >> tag_navi.log')
sys('navi tag --c "Corporate Agents" --v "Unitrends" --plugin 22869 --output "unitrends" >> tag_navi.log')

sys('echo new update')
# if we are going to do anything with the tags we created, we have to download the new tag information
# Lets give the tags a mintute to update in Tenable.io
time.sleep(60)
sys('navi update >> navi_update.log')

sys('echo Access groups')
# Use a Tag create an access group - For now, assign owners in the UI.
sys('navi agroup --name "Corporate Apps" -tag --c "Corporate Apps" --v "Jira" --usergroup "Corporate Apps" -scanview >> access_navi.log')
sys('navi agroup --name "Corporate Apps" -tag --c "Corporate Apps" --v "Confluence" --usergroup "Corporate Apps" -scanview >> access_navi.log')
sys('navi agroup --name "Custom Apps" -tag --c "Custom Apps" --v "New host" --usergroup "Custom Apps" -scanview >> access_navi.log')

sys('echo Delete then adds troubleshooting Tags')
# Find Assets that are taking a log time to scan; delete the tag first, so that you always have the latest data for scan issues
sys('navi delete tag --c "Scantime" --v "20 Minutes" >> tag_navi.log')
sys('navi delete tag --c "Scantime" --v "10 Minutes" >> tag_navi.log')
sys('navi delete tag --c "Scantime" --v "5 Minutes" >> tag_navi.log')
sys('navi delete tag --c "Credential Issues" --v "Cred Failure" >> tag_navi.log')
sys('navi delete tag --c "Credential Issues" --v "General Failure" >> tag_navi.log')

sys('echo Tagging by Scantime and Cred issues')
# Now create your Scan tags
sys('navi tag --c "Scantime" --v "20 Minutes" --scantime 20 >> tag_scan_navi.log')
sys('navi tag --c "Scantime" --v "10 Minutes" --scantime 10 >> tag_scan_navi.log')
sys('navi tag --c "Scantime" --v "5 Minutes" --scantime 5 >> tag_scan_navi.log')
sys('navi tag --c "Credential Issues" --v "Cred Failure" --plugin 104410 >> tag_navi.log')
sys('navi tag --c "Credential Issues" --v "General Failure" --plugin 21745 >> tag_navi.log')
end = time.time()

print("This script took: " + str((end-start)/60) + "Minutes")
