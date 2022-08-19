from os import system as sys
import time

# Instructions #

# Add/remove or adjust any of the below commands
# The structure is there to help you with the command syntax.

start = time.time()

# Replace 'access_key and secret_key with your keys
sys('navi keys --a <Your ACCESS KEY> --s <YOUR SECRET KEY>')

# Update the navi database for tagging on vulns
sys('navi update full')

sys('echo Adding User Groups')

# Create User Groups
sys('navi usergroup create --name "CentOS Systems"')
sys('navi usergroup create --name "Windows Systems"')
sys('navi usergroup create --name "IoT Devices"')
sys('navi usergroup create --name "Custom Apps"')
sys('navi usergroup create --name "Corporate Apps"')
sys('navi usergroup create --name "Networking Systems"')
sys('navi usergroup create --name "Corporate Systems"')
sys('navi usergroup create --name "Corporate Security"')

# Create Users
sys('navi user add --username "thor@tenable.com" --password "Dietcoke\!12345" --permission 16 --name "Thor" --email "thor@tenable.com"')
sys('navi user add --username "ironman@tenable.com" --password "Dietcoke\!12345" --permission 16 --name "Iron Man" --email "ironman@tenable.com"')
sys('navi user add --username "wasp@tenable.com" --password "Dietcoke\!12345" --permission 16 --name "The WASP" --email "wasp@tenable.com"')
sys('navi user add --username "antman@tenable.com" --password "Dietcoke\!12345" --permission 16 --name "Ant Man" --email "antman@tenable.com"')
sys('navi user add --username "blackwidow@tenable.com" --password "Dietcoke\!12345" --permission 16 --name "Black Widow" --email "black_widow@tenable.com"')
sys('navi user add --username "vison@tenable.com" --password "Dietcoke\!12345" --permission 16 --name "Vision" --email "vison@tenable.com"')
sys('navi user add --username "captain_america@tenable.com" --password "Dietcoke\!12345" --permission 64 --name "Captain America" --email "captain_america@tenable.com"')
sys('navi user add --username "hulk@tenable.com" --password "Dietcoke\!12345" --permission 16 --name "The Hulk" --email "hulk@tenable.com"')
sys('navi user add --username "hawkeye@tenable.com" --password "Dietcoke\!12345" --permission 16 --name "Dr strange" --email "hawkeye@tenable.com"')

sys('echo Waiting 30 seconds for T.io to process user and usergroup creation')
time.sleep(30)

# Add Users to their groups
sys('navi usergroup add --user "ironman@tenable.com" --name "CentOS Systems"')
sys('navi usergroup add --user "wasp@tenable.com" --name "Windows Systems"')
sys('navi usergroup add --user "antman@tenable.com" --name "IoT Devices"')
sys('navi usergroup add --user "blackwidow@tenable.com" --name "Custom Apps"')
sys('navi usergroup add --user "thor@tenable.com" --name "Corporate Apps"')
sys('navi usergroup add --user "vison@tenable.com" --name "Networking Systems"')
sys('navi usergroup add --user "hulk@tenable.com" --name "Corporate Systems"')
sys('navi usergroup add --user "hawkeye@tenable.com" --name "Corporate Security"')

# Tag assets based on Vulnerability Data
sys('navi tag --c "Custom Apps" --v "Jenkins" --plugin 22869 --output jenkins')
sys('navi tag --c "Custom Apps" --v "Docker" --plugin 93561')

sys('navi tag --c "Corporate Apps" --v "Confluence" --plugin 159464 --output confluence')
sys('navi tag --c "Corporate Apps" --v "Splunk" --plugin 22869 --output splunk')
sys('navi tag --c "Corporate Apps" --v "Jira" --plugin 131566')

sys('navi tag --c "Corporate Security" --v "Tenable Security Center" --plugin 71158')
sys('navi tag --c "Corporate Security" --v "Nessus Scanner" --plugin 10147 ')
sys('navi tag --c "Corporate Security" --v "Pi-Hole" --plugin 24260 --output "pi-hole"')

sys('navi tag --c "Corporate Systems" --v "VMWare" --plugin 20301')
sys('navi tag --c "Corporate Systems" --v "Unitrends" --plugin 35291 --output unitrends')
sys('navi tag --c "Corporate Systems" --v "Synology NAS" --plugin 72341')
sys('navi tag --c "Corporate Systems" --v "DNS Servers" --name "DNS Server"')

sys('navi tag --c "Network Systems" --v "PfSense Firewall" --plugin 106952')
sys('navi tag --c "Network Systems" --v "Netgear Switch" --plugin 54615 --output switch')
sys('navi tag --c "Network Systems" --v "Wireless Access Points" --plugin 10800 --output "UAP-AC-Pro"')

sys('navi tag --c "OS" --v "Windows" --plugin 11936 --output Windows')
sys('navi tag --c "OS" --v "CentOS" --name "CentOS"')

sys('navi tag --c "IoT" --v "Ipad or Iphone" --plugin 11936 --output Iphone')
sys('navi tag --c "IoT" --v "Ipad or Iphone" --plugin 11936 --output Ipad')
sys('navi tag --c "IoT" --v "Raspberry Pi" --plugin 10267 --output Raspbian')
sys('navi tag --c "IoT" --v "Nintendo" --plugin 10267 --output Nintendo')
sys('navi tag --c "IoT" --v "Chrome Cast" --plugin 10863 --output "Google TV"')

sys('echo Waiting 60 seconds for tenable.io to process our tag request')
time.sleep(60)

# Add permissions to Usergroups
sys('navi access create --c "Custom Apps" --v "Jenkins" --usergroup "Custom Apps" --perm CanView --perm CanScan --perm CanUse')
sys('navi access create --c "Custom Apps" --v "Docker" --usergroup "Custom Apps" --perm CanUse --perm CanView --perm CanScan --perm CanUse')

sys('navi access create --c "Corporate Apps" --v "Confluence" --usergroup "Corporate Apps" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "Corporate Apps" --v "Splunk" --usergroup "Corporate Apps" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "Corporate Apps" --v "Jira" --usergroup "Corporate Apps" --perm CanUse --perm CanView --perm CanScan')

sys('navi access create --c "Corporate Security" --v "Tenable Security Center" --usergroup "Corporate Security" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "Corporate Security" --v "Nessus Scanner" --usergroup "Corporate Security" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "Corporate Security" --v "Pi-Hole" --usergroup "Corporate Security" --perm CanUse --perm CanView --perm CanScan')

sys('navi access create --c "Corporate Systems" --v "VMWare" --usergroup "Corporate Systems" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "Corporate Systems" --v "Unitrends" --usergroup "Corporate Systems" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "Corporate Systems" --v "Synology NAS" --usergroup "Corporate Systems" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "Corporate Systems" --v "DNS Servers" --usergroup "Corporate Systems" --perm CanUse --perm CanView --perm CanScan')

sys('navi access create --c "Network Systems" --v "PfSense Firewall" --usergroup "Networking Systems" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "Network Systems" --v "Netgear Switch" --usergroup "Networking Systems" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "Network Systems" --v "Wireless Access Points" --usergroup "Networking Systems" --perm CanUse --perm CanView --perm CanScan')

sys('navi access create --c "OS" --v "Windows" --usergroup "Windows Systems" --perm CanUse --perm CanView --perm CanScan')

sys('navi access create --c "OS" --v "CentOS" --usergroup "CentOS Systems" --perm CanUse --perm CanView --perm CanScan')

sys('navi access create --c "IoT" --v "Ipad or Iphone" --usergroup "IoT Devices" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "IoT" --v "Ipad or Iphone" --usergroup "IoT Devices" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "IoT" --v "Raspberry Pi" --usergroup "IoT Devices" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "IoT" --v "Nintendo" --usergroup "IoT Devices" --perm CanUse --perm CanView --perm CanScan')
sys('navi access create --c "IoT" --v "Chrome Cast" --usergroup "IoT Devices" --perm CanUse --perm CanView --perm CanScan')
finish = time.time()

total = finish - start
mins = total/60

print("The Script took {} seconds or {} minutes".format(total, mins))

# clean up Directions

# Run "navi display users" -- grab first and last users IDs then run the below command
# sys('for user in {2254840..2254848}; do navi delete user $user; done')

# Run "navi display usergroups" -- grab first and last users IDS then run the below command
# for usergroup in {2254840..2254848}; do navi delete usergroup $usergroup; done


# Click all tags and delete, this will also delete any permissions associated - simpler than scripting
