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
import codecs

version = "1.1"

def ts2str(ts):
	hour_fromtime = datetime.fromtimestamp(ts).hour
	min_fromtime = datetime.fromtimestamp(ts).minute

	hour_utctime = datetime.utcfromtimestamp(ts).hour
	min_utctime = datetime.utcfromtimestamp(ts).minute

	hour_offset = (hour_fromtime - hour_utctime) * 100
	min_offset = ((min_fromtime - min_utctime) * 100) // 60

	gmt = hour_offset + min_offset
	gmt_abs = str(abs(gmt))

	if gmt >= 0:
		gmt_final = "+"+gmt_abs.zfill(4)
	else:
		gmt_final = "-"+gmt_abs.zfill(4)

	timeurlsnarf = str(datetime.utcfromtimestamp(ts).strftime('[%d/%m/%Y:%H:%M:%S {}]'.format(gmt_final)))

	return timeurlsnarf

def snifferHTTP(packet):
	if packet.haslayer(scapy_http.http.HTTPRequest):
		source_ip = str(packet["IP"].src)
		ts = int(packet["TCP"].time)
		timeurlsnarf = ts2str(ts)
		metodo = str(packet["HTTPRequest"].Method.decode("utf-8"))
		host = str(packet["HTTPRequest"].Host.decode("utf-8"))
		path = str(packet["HTTPRequest"].Path.decode("utf-8"))
		httpv = str(packet["HTTPRequest"].fields["Http-Version"].decode("utf-8"))
		useragent = str(packet["HTTPRequest"].fields["User-Agent"].decode("utf-8"))
		if packet["TCP"].dport == 80:
			port = ""
		else:
			port = ":"+str(codecs.decode(packet["TCP"].dport,encoding='utf-8',errors='ignore'))
		if metodo == "POST":
			data = ""
			if packet.haslayer(Raw):
				data = "?"+str(codecs.decode(packet["Raw"].load,encoding='utf-8',errors='ignore'))
			string_completo = source_ip + " - - " + timeurlsnarf + ' "' + metodo + " " + "http://" + host + port + path + data + " " + httpv + '" - - "-" "' + useragent + '"'
			print(string_completo)
		if metodo == "GET":
			string_completo = source_ip + " - - " + timeurlsnarf + ' "' + metodo + " " + "http://" + host + port + path + " " + httpv + '" - - "-" "' + useragent + '"'
			print(string_completo)


def usage():
	print("Version: "+version)
	print("Usage: python " + sys.argv[0] + " [-i interface | -p pcapfile]")

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
			print(sys.argv[0]+": listening on "+arg+" [tcp port 80 or port 8080 or port 3128]")
			scapy.sniff(iface=arg,filter="tcp port 80 or port 8080 or port 3128",prn=snifferHTTP)
		
	for opt, arg in opts:
		if opt in ("-p", "--pcap"):
			try:
				packets = scapy.rdpcap(arg)
				for packet in packets:
					snifferHTTP(packet)
			except scapy.Scapy_Exception as e:
				print(e)
				sys.exit(2)

	for opt, arg in opts:
		if opt in ("-h", "--help"):
			usage()
			sys.exit()

if __name__ == "__main__":
	try:
		main()
	except Exception as e:
		print(e)
