# -*- coding: utf-8 -*-

import hexdump
import socket

from TCP.PacketReceiver import packetReceiver
from TCP.Packet.packetEnum import packet_enum
from UDP.packetEnum import udp_packet_enum
from twisted.internet.protocol import Protocol

UDP_IP = "127.0.0.1"
UDP_PORT = 9340

class ClientProtocol(packetReceiver, Protocol):

    def __init__(self, factory):
        self.factory = factory
        self.factory.server.client = self
        self.server = self.factory.server
        self.crypto = self.server.crypto
        self.udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def connectionMade(self):
        self.peer = self.transport.getPeer()
        print('[*] Connected to {}:{}'.format(self.peer.host, self.peer.port))

    def connectionLost(self, reason):
        print('[*] Server closed the connection !')
        self.server.transport.loseConnection()

    def processPacket(self, packet_id, data):
        decrypted = self.crypto.decrypt_server_packet(packet_id, data[7:])

        if packet_id == 27579 and self.server.factory.args.udp:
            client_host = self.server.transport.getPeer().host

            decrypted = self.server.factory.udp_protocol.build_udp_info_packet(client_host, decrypted)

        encrypted = self.crypto.encrypt_server_packet(packet_id, decrypted)
        payload = packet_id.to_bytes(2, 'big') + len(encrypted).to_bytes(3, 'big') + data[5:7] + encrypted

        self.server.transport.write(payload)
        bstr = (packet_id).to_bytes(2, byteorder='big')
        if len(decrypted) < 40:
            self.udpsock.sendto(bstr+decrypted, (UDP_IP, UDP_PORT))

        packet_name = packet_enum.get(packet_id, udp_packet_enum.get(packet_id, packet_id))

        print('[*] {} received from server'.format(packet_name))

        if self.server.factory.args.verbose and decrypted:
            print(hexdump.hexdump(decrypted))

        if self.server.factory.args.replay:
            self.server.factory.replay.save_tcp_packet(packet_name, data[:7] + decrypted)

