# Navi - The Tenable.io Swiss Army Knife
A command-line tool which leverages the Tenable.io API to automate common tasks
in Cyber Exposure or Vulnerability Management.

    *** This tool is not an officially supported Tenable project ***
    
    *** Use of this tool is subject to the terms and conditions identified below,
     and is not subject to any license agreement you may have with Tenable ***

# Important Note

All documentation has been moved to the [Github wiki](https://github.com/packetchaos/navi/wiki) for more verbose documentation.

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
