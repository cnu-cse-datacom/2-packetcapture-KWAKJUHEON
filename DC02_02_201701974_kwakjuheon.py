import socket
import struct


def parsing_ethernet_header(data):
	ethernet_header = struct.unpack("!6c6c2s", data)
	ether_src = convert_ethernet_address(ethernet_header[0:6])
	ether_dest = convert_ethernet_address(ethernet_header[6:12])
	ip_header = "0x" + ethernet_header[12].hex()
	
	print("========ethernet header========")
	print("src_mac_address:", ether_src)
	print("dest_mac_address:", ether_dest)
	print("ip_version", ip_header)

def convert_ethernet_address(data):
	ethernet_addr = list()
	for i in data:
		ethernet_addr.append(i.hex())
	ethernet_addr = ":".join(ethernet_addr)
	return ethernet_addr

def parsing_ip_header(data):
	ip_header = struct.unpack("!B B H H H B B H 4s 4s", data[0][14:34])
	ip_version = (ip_header[0]&0xF0)>>4
	ip_Length = (ip_header[0]&0x0F)
	differenticated_service_codepoint = (ip_header[1] & 0xFC) >> 2
	explicit_congestion_notification = (ip_header[1] & 0x03)
	total_length = ip_header[2]
	identification = ip_header[3]
	flags = (ip_header[4] & 0xE000)>>13
	reserved_bit = (ip_header[4] & 0x8000)>>15
	not_fragments = (ip_header[4] & 0x4000)>>14
	fragments = (ip_header[4] & 0x2000)>>13
	fragments_offset = ip_header[4] & 0x1FFF
	time_to_live = ip_header[5]
	protocol = ip_header[6]
	header_checksum = ip_header[7]
	source_ip_address = socket.inet_ntoa(ip_header[8])
	dest_ip_address = socket.inet_ntoa(ip_header[9])

	print("========ip_header========")
	print("ip_version: ", ip_version)
	print("ip_Length: ", ip_Length)
	print("differentiated_service_codepoint: ", differenticated_service_codepoint)
	print("explicit_congestion_notification: ", explicit_congestion_notification)
	print("total_length: ", total_length)
	print("identification: ", identification)
	print("flags: ", flags)
	print(">>>reserved_bit: ", reserved_bit)
	print(">>>not_fragments: ", not_fragments)
	print(">>>fragments: ", fragments)
	print(">>>fragments_offset: ", fragments_offset)
	print("Time to live: ", time_to_live)
	print("protocol: ", protocol)
	print("header checksum: ", header_checksum)
	print("source_ip_address: ", source_ip_address)
	print("dest_ip_address: ", dest_ip_address)
	if protocol == 6:
		parsing_tcp_header(data[0][34:54])
	elif protocol == 17:
		parsing_udp_header(data[0][34:42])

def parsing_tcp_header(data):
	tcp_header = struct.unpack("! H H I I B B H H H", data)
	src_port = tcp_header[0]
	dec_port = tcp_header[1]
	seq_num = tcp_header[2]
	ack_num = tcp_header[3]
	header_len = (tcp_header[5]&0xF0)>>4
	flags = tcp_header[5]
	reserved = (tcp_header[5] & 0x1FF)>>9
	nonce = (tcp_header[5] & 0xEFF)>>8
	cwr = (tcp_header[5] & 0x7F)>>7
	urgent = (tcp_header[5] & 0xDF)>>5
	ack = (tcp_header[5] & 0xEF) >> 4
	push = (tcp_header[5] & 0x7) >> 3
	reset = (tcp_header[5] & 0xB) >> 2
	syn = (tcp_header[5] & 0xD) >> 1
	fin = (tcp_header[5] & 0xE)
	window_size_value = tcp_header[6]
	checksum = tcp_header[7]
	urgent_pointer = tcp_header[8]
	print("========tcp_header========")
	print("src_port: ", src_port)
	print("dec_port: ", dec_port)
	print("seq_num: ", seq_num)
	print("ack_num: ", ack_num)
	print("header_len: ", header_len)
	print("flags: ", flags)
	print(">>>reserved: ", reserved)
	print(">>>nonce: ", nonce)
	print(">>>cwr: ",cwr)
	print(">>>urgent: ", urgent)
	print(">>>ack: ", ack)
	print(">>>push: ", push)
	print(">>>reset: ", reset)
	print(">>>syn: ", syn)
	print(">>>fin: ", fin)
	print("window_size_value: ", window_size_value)
	print("checksum: ", checksum)
	print("urgent_pointer: ", urgent_pointer)

def parsing_udp_header(data):
	udp_header = struct.unpack("!H H H H", data)
	src_port = udp_header[0]
	dst_port = udp_header[1]
	leng = udp_header[2]
	header_checksum = udp_header[3]
	print("=========udp_header=========")
	print("src_port: ", src_port)
	print("dst_port: ", dst_port)
	print("leng: ", leng)
	print("header_checksum: ", header_checksum)

recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

print("<<<<<<<< Packet Capture Start >>>>>>>>")	
while True:
	data = recv_socket.recvfrom(20000)
	parsing_ethernet_header(data[0][0:14])
	parsing_ip_header(data)
