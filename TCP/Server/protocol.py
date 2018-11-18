# -*- coding: utf-8 -*-

import hexdump

from twisted.internet import reactor
from TCP.Client.factory import ClientFactory
from TCP.PacketReceiver import packetReceiver
from TCP.Packet.packetEnum import packet_enum
from UDP.packetEnum import udp_packet_enum
from twisted.internet.protocol import Protocol


class ServerProtocol(packetReceiver, Protocol):

    def __init__(self, factory):
        self.factory = factory
        self.factory.server = self
        self.crypto = self.factory.crypto
        self.client = None

    def connectionMade(self):
        self.peer = self.transport.getPeer()
        print('[*] New connection from {}'.format(self.peer.host))
        self.factory.client_endpoint.connect(ClientFactory(self))

    def connectionLost(self, reason):
        print('[*] Client disconnected !')
        if self.client:
            self.client.transport.loseConnection()

    def processPacket(self, packet_id, data):

        if not self.client:
            reactor.callLater(0.25, self.processPacket, packet_id, data)
            return

        packet_name = packet_enum.get(packet_id, udp_packet_enum.get(packet_id, packet_id))

        print('[*] {} received from client'.format(packet_name))

        decrypted = self.crypto.decrypt_client_packet(packet_id, data[7:])

        if self.factory.args.verbose and decrypted:
            print(hexdump.hexdump(decrypted))

        if self.factory.args.replay:
            self.factory.replay.save_tcp_packet(packet_name, data[:7] + decrypted)

        encrypted = self.crypto.encrypt_client_packet(packet_id, decrypted)
        payload = packet_id.to_bytes(2, 'big') + len(encrypted).to_bytes(3, 'big') + data[5:7] + encrypted

        self.client.transport.write(payload)
