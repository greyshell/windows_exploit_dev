#! /root/pentest/python-virtual-env/bin/python

# author: greyshell 
# acknowledged to: Mike Czumak's basic reconscan script


import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time
import optparse


def multProc(targetin, scanip, port, path):
	jobs = []
	p = multiprocessing.Process(target=targetin, args=(scanip,port, path))
	jobs.append(p)
	p.start()

	return


def safeBlock(CMD):
	try:
		results = subprocess.check_output(CMD, shell=True)
	except:
		print '\n[+] INFO: Exception occured during execution but handled gracefully'
		results = 'ERROR'
	finally:

		return results
	

def unicornPortProcessing(results):
	results = results.split("\n")
	port_all = '1'
	for line in results:
		temp = line[26:31]
		p = temp.strip()
		port_all = port_all + ',' + p

	return port_all


def httpEnum(ip_address, port, path):
	print "\n[+] INFO: Detected http on " + ip_address + ":" + port
	print "\n[+] INFO: Running nse http scripts for " + ip_address 
	CMD = "nmap -sV -Pn -p %s --script=http-enum,http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint -oN '%s/%s_nse_http_%s_result.txt' %s" % (port, path, ip_address, port, ip_address)
	print CMD	
	results = safeBlock(CMD)

	print "\n[+] INFO: Running nse-http compiled vulnscan scripts for " + ip_address 
	CMD = "nmap -sV -Pn -p %s --script=vulscan/vulscan.nse -oN '%s/%s_nse_http-VULSCAN_%s_result.txt' %s" % (port, path, ip_address, port, ip_address)
	print CMD
	results = safeBlock(CMD)
		
	return


def httpsEnum(ip_address, port, path):
	print "\n[+] INFO: Detected https on " + ip_address + ":" + port	
	print "\n[+] INFO: Running nse https scripts for " + ip_address 
	CMD = "nmap -sV -Pn -p %s --script=http-enum,http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oN '%s/%s_nse_https_%s_result.txt' %s" % (port, path, ip_address, port, ip_address)
	print CMD	
	results = safeBlock(CMD)

	print "\n[+] INFO: Running nse-http compiled vulnscan scripts for " + ip_address 
	CMD = "nmap -sV -Pn -p %s --script=vulscan/vulscan.nse -oN '%s/%s_nse_http-VULSCAN_%s_result.txt' %s" % (port, path, ip_address, port, ip_address)
	print CMD
	results = safeBlock(CMD)
	
	return


def mySqlEnum(ip_address, port, path):
	print "\n[+] INFO: Detected mySql on " + ip_address + ":" + port
	print "\n[+] INFO: Running nse mySql scripts for " + ip_address 
	CMD = "nmap -sV -Pn -p %s --script=mysql-empty-password,mysql-vuln-cve2012-2122 -oN '%s/%s_nse_mysql_%s_result.txt' %s" % (port, path, ip_address, port, ip_address)
	print CMD	
	results = safeBlock(CMD)
	
	return



def smtpEnum(ip_address, port, path):
	print "\n[+] INFO: Detected smtp on " + ip_address + ":" + port
	print "\n[+] INFO: Running nse SMTP  scripts for " + ip_address 
	CMD = "nmap -Pn -sV -p 25,465,587 --script=smtp-commands,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1764 -oN '%s/%s_nse_smtp_%s_result.txt' %s --open" % (path, ip_address, port, ip_address)
	print CMD	
	results = safeBlock(CMD)
	
	return


def ntpEnum(ip_address, port, path):
	print "\n[+] INFO: Detected NTP on " + ip_address + ":" + port
	print "\n[+] INFO: Running nse NTP  scripts for " + ip_address 
	CMD = "nmap -Pn -sU -p 123 --script=ntp-info -oN '%s/%s_nse_ntp_result.txt' %s" % (path, ip_address, ip_address)
	print CMD	
	results = safeBlock(CMD)

	return


def rdpEnum(ip_address, port, path):
	print "\n[+] INFO: Detected test on " + ip_address + ":" + port
	print "\n[+] INFO: Running nse RDP  scripts for " + ip_address 
	CMD = "nmap -Pn -sV -p %s --script=rdp-enum-encryption -oN '%s/%s_nse_rdp_result.txt' %s" % (port, path, ip_address, ip_address)
	print CMD	
	results = safeBlock(CMD)

	return


def ftpEnum(ip_address, port, path):
	print "\n[+] INFO: Detected ftp on " + ip_address + ":" + port
	
	print "\n[+] INFO: Performing nmap FTP script scan for " + ip_address + ":" + port
	FTPSCAN = "nmap -sV -Pn -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 %s > %s/%s_%s_nsc_ftp.txt" % (port, ip_address, path, ip_address, port)
	print FTPSCAN
	results = safeBlock(FTPSCAN)
	
	return


def smbEnum(ip_address, port, path):
	print "[+] INFO: Detected SMB on " + ip_address

	print "\n[+] INFO: Performing nbtscan scan for " + ip_address
	NBT = "nbtscan -r %s >> %s/%s_nbtscan.txt" % (ip_address, path, ip_address)
	print NBT
	results = safeBlock(NBT)
	NBT = "nbtscan -hv %s >> %s/%s_nbtscan.txt" % (ip_address, path, ip_address)
	print NBT
	results = safeBlock(NBT)
	
	print "\n[+] INFO: Performing linux4enum for " + ip_address
	LNX = "enum4linux -a %s >> %s/%s_linux4enum.txt" % (ip_address, path, ip_address)
	print LNX
	results = safeBlock(LNX)

	print "\n[+] INFO: Performing smb-check-vulns.nse for " + ip_address
	CMD = "nmap -Pn -sU -sS -pT:139,445,U:137 --script=nbstat,samba-vuln-cve-2012-1182,smb-enum-domains,smb-system-info,smb-vuln-ms10-054,smb-vuln-ms10-061,smbv2-enabled -oN '%s/%s_nse_smb_result.txt' %s --open" % (path, ip_address, ip_address)
	print CMD
	results = safeBlock(CMD)
	
	return


def snmpEnum(ip_address, port, path):
	print "[+] INFO: Detected snmp on " + ip_address + ":" + port
	key = 'public'
	print "\n[+] INFO: Running nse script to find snmp community string " + ip_address 
	CMD = "nmap -Pn -sU -p 161,162 %s --open --script snmp-brute --script-args snmp-brute.communitiesdb=/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt -oN '%s/%s_snmp_nse_result.txt'" % (ip_address, path, ip_address)
	print CMD	
	results = safeBlock(CMD)
	
	# processing the nse script result
	resultarr = results.split("\n")
	
	for result in resultarr:
		if "Valid" in result:
			a, k, c, d, e = result.split()
			print "[*] Valid snmp community string found through brute force: " + k
			key = k
		
	print "\n[+] INFO: Running snmpcheck " + ip_address 
	CMD = "snmpcheck -c %s -t %s >> %s/%s_snmpcheck.txt" % (key, ip_address, path, ip_address)
	print CMD
	results = safeBlock(CMD)

	return


def portScan(ip_address):
	ip_address = ip_address.strip()
	serv_dict = {}

	# creating output folder inside current directory
	
	TST = "pwd"
	results = subprocess.check_output(TST, shell=True)
	a = results.split("\n")
	path = a[0]
	
	existing_dir = ip_address + '_enum_results'
	
	if os.path.isdir(existing_dir):
		pass
		print "\n[+] INFO: Old scan directory is identified and removed"
		TST = "rm -rf %s " %existing_dir
		results = subprocess.check_output(TST, shell=True)

	print "\n[+] INFO: Creating new scan directory %s_enum_results" %ip_address
		
	TST = "mkdir %s_enum_results"%ip_address
	results = subprocess.check_output(TST, shell=True)

	path = path + '/' + ip_address + '_enum_results'

	print "\n[+] INFO: Performing xprobe2 OS scan for " + ip_address
	XPROBE = "xprobe2 %s > %s/%s_xprobe_os.txt" % (ip_address, path, ip_address)
	print XPROBE
	results = safeBlock(XPROBE)
	

	print "\n[+] INFO: Running unicorn TCP all port scan for " +ip_address
	UNICORNTCP_ALL = "unicornscan -m T %s:1-65535" %ip_address
	print UNICORNTCP_ALL
	results = safeBlock(UNICORNTCP_ALL)

	outfile = path + '/' + ip_address +'_unicorn_tcp_all.txt'
	f = open(outfile, "w")
	f.write(results)
	f.flush()
	f.close

	all_ports = unicornPortProcessing(results)
	all_ports = all_ports[2:-1]			
	
	if all_ports == "":
		print "\n[+] INFO: Running independent nmap TCP scan for " + ip_address
		# nmap scans particular TCP ports that has been already identified by unicornscan
		TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 3 --top-ports 2000 -oN '%s/%s_nmap_tcp_top_ports.txt' %s --open" % (path, ip_address, ip_address)
		print TCPSCAN
		results = safeBlock(TCPSCAN)
	else:
		print "\n[+] INFO: Running nmap TCP scan for " + ip_address
		# nmap scans particular TCP ports that has been already identified by unicornscan
		TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 3 -p %s -oN '%s/%s_nmap_tcp_all.txt' %s --open" % (all_ports, path, ip_address, ip_address)
		print TCPSCAN
		results = safeBlock(TCPSCAN)
	
	
	# processing TCP ports
	lines = results.split("\n")
	for line in lines:
		ports = []
		line = line.strip()
		if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
			while "  " in line: 
				line = line.replace("  ", " ");
			linesplit= line.split(" ")
			service = linesplit[2] # grabbing the service name
			port = line.split(" ")[0] # grabbing the port/proto
			if service in serv_dict:
				ports = serv_dict[service] # if the service is already in the dict, grab the port list
			ports.append(port) 
			serv_dict[service] = ports # add service to the dictionary along with the associated port(2)


	print "\n[+] INFO: Running unicorn default UDP port scan for " +ip_address
	UNICORNUDP = "unicornscan -m U %s" %ip_address
	
	print UNICORNUDP

	results = safeBlock(UNICORNUDP)
	outfile = path + '/' + ip_address +'_unicorn_udp.txt'
	f = open(outfile, "w")
	f.write(results)
	f.flush()
	f.close

	uni_ports = unicornPortProcessing(results)
	uni_ports = uni_ports[2:-1]

	if uni_ports == "":
		print "\n[+] INFO: Running independent nmap UDP scan for " + ip_address
		# nmap scan default UDP ports
		UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 3 --top-ports 10 -oN '%s/%s_nmap_UDP.txt' %s --open" % (path, ip_address, ip_address)
		print UDPSCAN
		udpresults = safeBlock(UDPSCAN)
	else:
		print "\n[+] INFO: Running nmap UDP scan for " + ip_address
		# nmap scans particular UDP port that has been already identified by unicornscan
		UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 3 -p %s -oN '%s/%s_nmap_udp.txt' %s --open" % (uni_ports, path, ip_address, ip_address)
		print UDPSCAN
		udpresults = safeBlock(UDPSCAN)

	
	# processing UDP ports
	udplines = udpresults.split("\n")
	for line in udplines:
		ports = []
     		line = line.strip()
     		if ("udp" in line) and ("open" in line) and not ("Discovered" in line):
	 		while "  " in line: 
            			line = line.replace("  ", " ");
        		linesplit= line.split(" ")
         		service = linesplit[2] # grabbing the service name
	 		port = line.split(" ")[0] # grabbing the port/proto
         		if service in serv_dict:
	    			ports = serv_dict[service] # if the service is already in the dict, grab the port list
         		ports.append(port) 
	 		serv_dict[service] = ports 
	
	# setting FLAGS
	smb_flag = 'true'
	
	for serv in serv_dict: 
		ports = serv_dict[serv]
		
		if ("ftp" in serv):
			for port in ports:
				port = port.split("/")[0]
				multProc(ftpEnum, ip_address, port, path)

		elif ("microsoft-ds" in serv) or ("netbios" in serv):
			for port in ports:
				port = port.split("/")[0]
				if smb_flag == 'true':
					smb_flag = 'false'
					multProc(smbEnum, ip_address, port, path)

		elif ("snmp" in serv):
			for port in ports:
				port = port.split("/")[0]
				multProc(snmpEnum, ip_address, port, path)

		elif ("ntp" in serv):
			for port in ports:
				port = port.split("/")[0]
				multProc(ntpEnum, ip_address, port, path)

		elif ("mysql" in serv):
			for port in ports:
				port = port.split("/")[0]
				multProc(mySqlEnum, ip_address, port, path)

		elif ("ms-wbt-server" in serv):
			for port in ports:
				port = port.split("/")[0]
				multProc(rdpEnum, ip_address, port, path)

		elif ("smtp" in serv):
			for port in ports:
				port = port.split("/")[0]
				multProc(smtpEnum, ip_address, port, path)

		elif ("http" in serv):
			for port in ports:
				port = port.split("/")[0]
				multProc(httpEnum, ip_address, port, path)

		elif ("https" in serv):
			for port in ports:
				port = port.split("/")[0]
				multProc(httpsEnum, ip_address, port, path)
	
	return


if __name__=='__main__':

	# adding parser functionality
	parser = optparse.OptionParser('python %prog -H' + ' <target host>')

	parser.add_option('-H', dest='host', type='string', help='specify target host')
	parser.add_option('-M', dest='targets', type='string', help='provide a text file (i.e. targets.txt) to scan multiple hosts where each host should be separated by a new line')
	
	(options, args) = parser.parse_args()

	host = options.host
	targets = options.targets
	

	if (host == None) & (targets == None):
		print 'Usage: python extractor.py -H <target host>'
	

	elif (host != None) & (targets != None):
		print "Usage(single host): python extractor.py -H <target host>"
		print 'Usage(multiple hosts): python extractor.py -M <targets.txt>'
		
		
		
	elif (host != None) & (targets == None):
		scanip = host
		jobs = []
		p = multiprocessing.Process(target=portScan, args=(scanip,))
		jobs.append(p)
		p.start()
		
		
	elif (host == None) & (targets != None):
		f = open(targets, 'r')
		for scanip in f:
			jobs = []
			p = multiprocessing.Process(target=portScan, args=(scanip,))
			jobs.append(p)
			p.start()
		
		f.close()
	
	
	# end of main	

	

