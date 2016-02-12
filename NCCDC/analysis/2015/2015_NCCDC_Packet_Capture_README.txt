README for 2015 National Collegiate Cyber Defense Competition packet capture

These logs are the traffic captures from the 2015 National CCDC Championship held in San Antonio, TX April 24-26, 2015.  The NCCDC uses a star topology where each competing team and each major group (Red Team, Orange Team, White Team, etc.) are connected to a core switch.  These logs were captured from the SPAN port on that core switch.  As there was over 1 TB of captured traffic, the packet captures are serialized into 500MB files and divided between day one and day two of the competition.  Packet captures were accomplished using tcpdump with DNS resolution disabled and were gzipped at the end of the competition to save space.  These packet captures contain traffic from automated scoring systems, traffic generators, live users, a live Red Team, and the competition.  For more information on the NCCDC please visit nccdc.org.

The 2015 NCCDC had 10 competing teams, Teams 1 through 10, which were tasked with operating and securing assets on the following subnets:
	Team 1 10.10.10.0 and 172.16.10.0 
	Team 2 10.20.20.0 and 172.16.20.0 
	Team 3 10.30.30.0 and 172.16.30.0 
	Team 4 10.40.40.0 and 172.16.40.0 
	Team 5 10.50.50.0 and 172.16.50.0  
	Team 6 10.60.60.0 and 172.16.60.0  
	Team 7 10.70.70.0 and 172.16.70.0  
	Team 8 10.80.80.0 and 172.16.80.0  
	Team 9 10.90.90.0 and 172.16.90.0 
	Team 10 10.100.100.0 and 172.16.100.0

On the "10" nets, each team was provided with a "core" network consisting of 8 servers (running a mix of BSD, Debian, Fedora, Windows Server 2008, ESXi 5.5, Windows 2008 R2, and Solaris X86), 6 workstations (running a mix of Windows 10, Windows XP, Ghost BSD, and Windows 7), 1 Cisco VoIP phone, 1 Juniper EX2200, and 1 Juniper SRX210.  Each core network contained a "canary" box on the 10.X.X.250 address that was not under the team's control and was used by the competition staff to monitor the status of the team's networks.  On the "172" networks, each team was provided with two "remote" networks simulating a Control Center and Plant facility for a small electrical utility company.  Both the Plant and Control networks were NAT'd behind a Juniper SRX240 for each team with the Plant network only accessible from within the Control Center network.  The Control Center network consisted of an RDP server, an FTP server, an HMI Workstation, an HMI server, an Engineering Workstation, an OPC server, and NMIS server, and an IDS.  Teams were required to have the following core services available to any IP address at all times during the competition:
   
DNS service on 10.X.X.5
HTTP service on 10.X.X.10 (webmail)
SMTP service on 10.X.X.10
POP3 service on 10.X.X.10 
HTTP service on 10.X.X.15 (e-commerce site)
HTTP service on 10.X.X.205 (ticket system)
SSH service on 172.16.X.204 (OPC server)
SSH service on 172.16.X.210 (end works)
FTP service on 172.16.X.203 (historian)
HTTP service on 172.16.X.211 (audit)


