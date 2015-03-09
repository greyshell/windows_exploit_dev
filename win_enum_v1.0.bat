rem Description: Windows basic enumeration scrip
rem Author: greyshell

rem ------------------------------------ Host and user details ------------------------------------------

echo 1. Finding os details > my_win_enum_report.txt
echo --------------------- >> my_win_enum_report.txt
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt


echo 2. Finding hostname >> my_win_enum_report.txt
echo --------------------- >> my_win_enum_report.txt
hostname >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt

echo 3. Finding exploited user name >> my_win_enum_report.txt
echo --------------------- >> my_win_enum_report.txt
echo %username% >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt


echo 4. All users on the system >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
net users >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt


echo 5. Getting group membership, active sessions, account lock out policy >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
net user %username% >> my_win_enum_report.txt
net users >> my_win_enum_report.txt
net session  >> my_win_enum_report.txt
net accounts /domain  >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt


echo 5.1. Display which group policies are applied and info about the OS if victim is the member of a domain: >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
gpreport >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt


rem ------------------------------------ Network details ------------------------------------------

echo 6. Checking available network interfaces and routing table >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
ipconfig /all >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt

echo 7. routing table >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
route print >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt



echo 8. Checking ARP cache table for all available interfaces >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
arp -A >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt


echo 9. Checking active network connections >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
netstat -ano >> my_win_enum_report.txt
netstat -an | find /i "established" >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt



echo 9.1. Checking hidden, non-hidden share  >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
net share >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt


echo 9.2. list all the hosts on the "compromised host's domain" and list the domains that the compromised host can see >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
net view >> my_win_enum_report.txt
net view /domain >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt


echo 9.3. enumerate all users on the domain >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
net group "domain user" /domain
net localgroup users /domain
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt




rem ------------------------------------ Firewall details ------------------------------------------

echo 10. The netsh firewall state >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
netsh firewall show state >> my_win_enum_report.txt
netsh firewall show opmode >> my_win_enum_report.txt
netsh firewall show port >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt


echo 11. Firewall configuration >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
netsh firewall show config >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt



rem ------------------------------------ Process and service details ------------------------------------------


echo 12. Scheduled tasks >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
schtasks /query /fo LIST /v >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt

echo 13. Running processes >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
tasklist /SVC >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt

echo 13.1. System variable and paths >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
set >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt

echo 14. Started windows services >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
net start >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt

echo 15. Installed 3rd party drivers >> my_win_enum_report.txt
echo --------------------------- >> my_win_enum_report.txt
DRIVERQUERY >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt
echo. >> my_win_enum_report.txt



