#!/usr/bin/env python
try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import scapy_http.http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

from datetime import datetime

import getopt
import sys

version = "1.0"

def snifferHTTP(packet):
	if packet.haslayer(scapy_http.http.HTTPRequest):
		source_ip = str(packet["IP"].src)
		ts = int(packet["TCP"].time)
		timeurlsnarf = str(datetime.fromtimestamp(ts).strftime('[%d/%m/%Y:%H:%M:%S %z]'))
		metodo = str(packet["HTTPRequest"].Method)
		host = str(packet["HTTPRequest"].Host)
		path = str(packet["HTTPRequest"].Path)
		httpv = str(packet["HTTPRequest"].fields["Http-Version"])
		useragent = str(packet["HTTPRequest"].fields["User-Agent"])
		if packet["TCP"].dport == 80:
			port = ""
		else:
			port = ":"+str(packet["TCP"].dport)
		if metodo == "POST":
			data = str("?"+packet["Raw"].load)
			string_completo = source_ip + " - - " + timeurlsnarf + ' "' + metodo + " " + "http://" + host + port + path + data + " " + httpv + '" - - "-" "' + useragent + '"'
			print(string_completo)
		else:
			string_completo = source_ip + " - - " + timeurlsnarf + ' "' + metodo + " " + "http://" + host + port + path + " " + httpv + '" - - "-" "' + useragent + '"'
			print(string_completo)


def usage():
	print("Version: "+version)
	print("Usage: ./" + sys.argv[0] + " [-i interface | -p pcapfile]")

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "i:p:h", ["interface","pcap","help"])
		if not opts:
				usage()
	except getopt.GetoptError as err:
		print(err)
		usage()
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("-i", "--interface"):
			try:
				print(sys.argv[0]+": listening on "+arg+" [tcp port 80 or port 8080 or port 3128]")
				scapy.sniff(iface=arg,filter="tcp port 80 or port 8080 or port 3128",prn=snifferHTTP)
			except PermissionError:
				print(sys.argv[0]+": "+arg+": You don't have permission to capture on that device (socket: Operation not permitted)")
				sys.exit(2)
			except scapy.Scapy_Exception as e:
				print("[-] Error:",e)
				sys.exit(2)
        
	for opt, arg in opts:
		if opt in ("-p", "--pcap"):
			try:
				packets = scapy.rdpcap(arg)
				for packet in packets:
					snifferHTTP(packet)
			except scapy.Scapy_Exception as e:
				print("[-] Error:",e)
				sys.exit(2)

	for opt, arg in opts:
		if opt in ("-h", "--help"):
			usage()
			sys.exit()

if __name__ == "__main__":
    main()
