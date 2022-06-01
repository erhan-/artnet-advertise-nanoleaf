#
# All major work by lightguru Domas (@dzelionis / https://www.linkedin.com/in/dzelionis) 
#

import sys
import time
from socket import (socket, inet_aton, AF_INET, SOL_SOCKET, SOCK_DGRAM, SO_BROADCAST, SO_REUSEADDR)
from struct import unpack, pack_into
import random
import threading
from nanoleafapi import Nanoleaf

UDP_IP = "192.168.52.55"
UDP_PORT = 6454 #0x1936 # Art-net is supposed to only use this port
BROADCAST_IP = "192.168.52.255"
NANOLEAF_IP = "192.168.52.56"

class NanoLeafSender:

    def __init__(self, nanoleaf_host, offset):
        self.nanoleaf_host = nanoleaf_host
        self.offset = offset
        self.nanoleaf_socket = socket(AF_INET, SOCK_DGRAM, 0)
        self.nl = Nanoleaf(self.nanoleaf_host)
        self.nl.create_auth_token()
        self.nl.enable_extcontrol()
        self.panel_ids = self.nl.get_ids()
        n_panels = len(self.panel_ids) - 1
        self.n_panels_b = n_panels.to_bytes(2, "big")
    
    def send_nanoleaf_data(self, packet_data):
        send_data = b""
        send_data += self.n_panels_b

        transition = 0

        for count, panel_id in enumerate(self.panel_ids):
            if panel_id != 0:
                offset = self.offset
                panel_id_b = panel_id.to_bytes(2, "big")
                send_data += panel_id_b
                red = packet_data[offset+3*count+0]
                send_data += red.to_bytes(1, "big")
                green = packet_data[offset+3*count+1]
                send_data += green.to_bytes(1, "big")
                blue = packet_data[offset+3*count+2]
                send_data += blue.to_bytes(1, "big")
                white = 0
                send_data += white.to_bytes(1, "big")
                send_data += transition.to_bytes(2, "big")

        self.nanoleaf_socket.sendto(send_data, (self.nanoleaf_host, 60222))

class ArtnetPacket:
 
    ARTNET_HEADER = b'Art-Net\x00'
    OP_OUTPUT = 0x5000
    POLL = 0x2000
    POLLREPLY = 0x2100
    sock = object()
    macs_dict = {}

    def __init__(self):
        self.op_code = None
        self.ver = None
        self.sequence = None
        self.physical = None
        self.universe = None
        self.length = None
        self.data = None

    def init_socket(self):
        try:
            self.sock = socket(AF_INET, SOCK_DGRAM)
        except:
            print("failed to init socket")

        print(("Listening in {0}:{1}").format(UDP_IP, UDP_PORT))

        self.sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.sock.bind((UDP_IP, 6454))


    def send_pollreply(self, packet):
        self.sock.sendto(packet, (BROADCAST_IP, UDP_PORT))
        self.sock.sendto(packet, ('255.255.255.255', 6454))

    def _gen_mac(self):
        return str(hex(random.randint(1, 255))).lstrip("0x")

    def gen_mac(self):
        mac = ""
        for i in range(0,6):
            if i == 0:
                mac = self._gen_mac()
            else:
                mac += f':{self._gen_mac()}'

        return mac

    def ip2long(self, ip):
    #"""
    #Convert an IP string to long
    #"""
        packedIP = inet_aton(ip)
        return unpack("!L", packedIP)[0]

    def pollreplay(self, adv_ip):
        ip = adv_ip

        packet = bytearray(239)
        offset = 0

        # Adding artnet header
        data = (0x41, 0x72, 0x74, 0x2d, 0x4e, 0x65, 0x74, 0x00)
        offset += len(data)
        pack_into('bbbbbbbb', packet, 0, *data)

        # Adding OpCode
        pack_into('H', packet, offset, self.POLLREPLY)
        offset += 2

        # adding ip
        ipInt = self.ip2long(ip)
        pack_into("!L", packet, offset, ipInt)
        offset += 4

        # adding port
        port = 6454
        pack_into("H", packet, offset, port)
        offset += 2

        # Version Info
        version_info = 0x0000 # 4bites
        net_switch = 0x00 # 2bites
        sub_switch = 0x00 # 2bites
        oem = 0xffff # 4bites
        ubea = 0x00 # 2bites
        status = 0xf0 # 2bites
        ESTA = 0xffff # 4bites

        data = (0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xf0, 0xff, 0xff)
        pack_into(  "BBBBBBBBBB", packet, offset, *data)
        offset += len(data)

        # sort name
        # 18x2 bites
        sort_name = "Artnet Nanoleaf"
        pack_into("!18s",packet,offset, sort_name.encode())
        offset += 18

        # long name
        # 3lines x 16hex  x2 bits =  48 x2 = 96
        long_name = "Artnet Nanoleaf - Test wrapper"
        pack_into("!48s", packet, offset, long_name.encode())
        offset += 48

        offset += 64
        offset += 16

        # port info
        number_of_ports = (0x00, 0x02)
        port_types = (0x40,0x40,0x00,0x00)
        input_status = (0x00,0x00,0x00,0x00)
        output_status = (0x00, 0x00,0x00,0x00)
        input_sub_switch = (0x00, 0x01, 0x00, 0x00)
        output_sub_switch = (0x00, 0x00,0x00,0x00)
        pack_into("BBBBBBBBBBBBBBBBBBBBBB", packet, offset, *number_of_ports, *port_types, *input_status,
                  *output_status, *input_sub_switch, *output_sub_switch)

        offset += len(number_of_ports + port_types + input_status + output_status + input_sub_switch + output_sub_switch)

        # swvideo + swmacro + swremote + spare + style
        data = [0x00] + [0x00] + [0x00] + [0x00, 0x00, 0x00] + [0x00]
        data = tuple(data)
        pack_into("BBBBBBB", packet, offset, *data)
        offset += len(data)

        # mac address
        if ip not in self.macs_dict.keys():
            mac = self.gen_mac()
            self.macs_dict[ip] = mac

        else:
            mac = self.macs_dict[ip]

        macSet = []
        tmpList = mac.split(":")

        for item in tmpList:
            macSet.append(int(f'0x{item}',16))
        pack_into("BBBBBB", packet, offset, *tuple(macSet))

        offset += 6

        bind_ip_address = UDP_IP
        # adding ip
        ipSet = []
        octets = bind_ip_address.split(".")
        for item in octets:
            ipSet.append(int(item))
        pack_into("!HHHH", packet, offset, *tuple(ipSet))
        offset += 4

        return packet

    def unpack_raw_artnet_packet(self,raw_data):
 
        if unpack('!8s', raw_data[:8])[0] != ArtnetPacket.ARTNET_HEADER:
            return None
 
        packet = ArtnetPacket()
 
        # We can only handle data packets
        (packet.op_code,) = unpack('H', raw_data[8:10])
        if packet.op_code == ArtnetPacket.POLL:
            print("received POLL packet, sending advertisement...")
            self.send_pollreply(self.pollreplay(UDP_IP))
        

        elif packet.op_code == ArtnetPacket.OP_OUTPUT:  
            (packet.op_code, packet.ver, packet.sequence, packet.physical,
                packet.universe, packet.length) = unpack('!HHBBHH', raw_data[8:18])
    
            (packet.universe,) = unpack('<H', raw_data[14:16])
    
            (packet.data,) = unpack(
                '{0}s'.format(int(packet.length)),
                raw_data[18:18+int(packet.length)])
            nanoleaf.send_nanoleaf_data(packet.data)
            

a = ArtnetPacket()
a.init_socket()
sock = a.sock

def artnet_receiver(UNIV=None, callBack=None):
    sequence = 0
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            (sequence_in) = unpack('B', data[12:13])
            if sequence_in == sequence:
                continue
            sequence = sequence_in
            
            processing_thread = threading.Thread(target=a.unpack_raw_artnet_packet, args=(data,))
            processing_thread.start()

        except KeyboardInterrupt:
            pass
            sock.close()
            sys.exit()

dmx_offset = 100
nanoleaf = NanoLeafSender(NANOLEAF_IP, dmx_offset)

def cb(data):
    nanoleaf.send_nanoleaf_data(data)

def artnet_worker():
    artnet_receiver(callBack=cb, UNIV=0)

art = threading.Thread(target=artnet_worker, args=())
art.start()

while True:
    a.send_pollreply(a.pollreplay(UDP_IP))
    time.sleep(2)
