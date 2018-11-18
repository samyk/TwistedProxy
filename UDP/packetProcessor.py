# -*- coding: utf-8 -*-

from queue import Queue
from threading import Thread
from TCP.Packet.reader import Reader
from UDP.packetEnum import udp_packet_enum


class packetProcessor(Thread):

    def __init__(self, connection_dict, replay):
        self.queue = Queue()
        self.replay = replay
        self.is_running = True
        self.reader = Reader(b'')
        self.connection_dict = connection_dict
        Thread.__init__(self)

    def run(self):
        while self.is_running:
            host, packet = self.queue.get()

            if packet is not None:
                if len(packet) != 1400:
                    self.reader.reinit(packet)
                    packet_list = []

                    session_id = self.reader.read(10)
                    host_dict = self.connection_dict[session_id][host]

                    if self.reader.has_remaining_bytes:
                        acks_count = self.reader.read_vint()

                        for i in range(acks_count):
                            self.reader.read_byte()

                        if self.reader.has_remaining_bytes:
                            chunks_count = self.reader.read_vint()

                            for i in range(chunks_count):
                                sequence_id = self.reader.read_byte()
                                packet_id = self.reader.read_vint()
                                packet_length = self.reader.read_vint()

                                packet_list.append({
                                                    'id': packet_id,
                                                    'packet_length': packet_length,
                                                    'sequence_id': sequence_id,
                                                    'payload': self.reader.read(packet_length)
                                                    })

                            for packet in reversed(packet_list):
                                if packet['sequence_id'] == host_dict['next_sequence_id']:
                                    packet_name = udp_packet_enum.get(packet['id'], packet['id'])
                                    print('[*] Received UDP chunk {} from {}, chunk length: {}'.format(
                                                                                                packet_name,
                                                                                                host,
                                                                                                packet['packet_length']))

                                    host_dict['next_sequence_id'] = (host_dict['next_sequence_id'] + 1) & 0xff
                                    decrypted = host_dict['crypto'].decrypt(packet['payload'])

                                    self.replay.save_udp_packet(session_id, packet_name, decrypted)

            self.queue.task_done()

    def stop(self):
        # Put a None packet in queue so it loop if queue is empty
        # then self.is_running is checked and while loop will be stoped
        self.queue.put([None, None])
        self.is_running = False

        if self.connection_dict:
        	self.replay.increment_index(self.replay.udp_session_index_path, self.replay.get_index(self.replay.udp_session_index_path))
