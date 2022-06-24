# LLFF
Live Linux Forensic Framework developed in Python/Flask. It allows us to quickly perform forensics on a running Linux system.  
Some of its capabilities:
* Processes:
  * View full list of running processes.
  * Inspect processs memory map and fetch memory strings easily.
  * Dump process core.
  * Allows to upload process' executable to VirusTotal for examination.
  * List connections made by a process.
  * List files opened by a process.
* Users:
  * View detailed list of user accounts.
* files:
  * Search for suspicious files by regex/name
* Network:
  * View detailed list of ports and connections opened on the system.
  * WHOIS lookup for raddr.
* Logs:
  * Syslog.
  * Auth log.
  * Ufw log.
  * Bash history.
* Services:
  * List all loaded services and their state.
* Anti-rootkit:
  * Chkrootkit to examine for signs of rootkits on the system.
  
### Notes
You're gonna need to install Chckrootkit (it's open source).  
To upload files to VT you need a VirusTotal API key (free).  
Since the forensics is done via Flask's web app running on the Linux machine, you can use NGINX reverse proxy with basic auth and SSL for secure remote access to the investigated system.  
Tested on Debian 11 Bullseye.
