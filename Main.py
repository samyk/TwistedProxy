# -*- coding: utf-8 -*-

import os
import json
import time
import frida
import argparse

from Replay import Replay
from TCP.Crypto import Crypto
from twisted.internet import reactor
from TCP.Server.factory import ServerFactory
from TCP.Server.endpoint import ServerEndpoint
from TCP.Client.endpoint import ClientEndpoint

from UDP.protocol import UDPProtocol


MAX_FRIDA_RETRY = 10


def onClose(udp_protocol):
        print("[*] Closing proxy !")

        if udp_protocol is not None:
            udp_protocol.packetProcessor.stop()


def start_frida_script(network):
    # Would be better to use frida.get_usb_device().spawn to spawn the app
    # But it seems that it is broken on some version so we use adb to spawn the game
    os.system("adb shell monkey -p com.supercell.clashroyale -c android.intent.category.LAUNCHER 1")
    time.sleep(0.5)

    try:
        if network:
            device = frida.get_remote_device()
        else:
            device = frida.get_usb_device()

    except Exception as exception:
        print('[*] Can\'t connect to your device ({}) !'.format(exception.__class__.__name__))
        exit()

    retry_count = 0
    process = None

    while not process:
        try:
            process = device.attach('com.supercell.clashroyale')

        except Exception as exception:
            if retry_count == MAX_FRIDA_RETRY:
                print('[*] Can\'t attach frida to the game ({}) ! Start the frida server on your device'.format(exception.__class__.__name__))
                exit()

            retry_count += 1
            time.sleep(0.5)

    print('[*] Frida attached !')

    if os.path.isfile("urandom_hook.js"):
        script = process.create_script(open("urandom_hook.js").read())

    else:
        print('[*] urandom_hook.js script is missing, cannot inject the script !')
        exit()

    script.load()

    print('[*] Script injected !')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Python proxy used to decrypt all clash royale game traffic')
    parser.add_argument('-f', '--frida', help='inject the frida script at the proxy runtime', action='store_true')
    parser.add_argument('-n', '--network', help='connect to frida via network rather than USB', action='store_true')
    parser.add_argument('-v', '--verbose', help='print packet hexdump in console', action='store_true')
    parser.add_argument('-r', '--replay', help='save packets in replay folder', action='store_true')
    parser.add_argument('-u', '--udp', help='start the udp proxy', action='store_true')

    args = parser.parse_args()

    if os.path.isfile('config.json'):
        config = json.load(open('config.json'))

    else:
        print('[*] config.json is missing !')
        exit()

    if args.frida:
        start_frida_script(args.network)

    crypto = Crypto(config['ServerKey'])
    replay = Replay(config['ReplayDirectory'])

    client_endpoint = ClientEndpoint(reactor, config['Hostname'], config['Port'])
    server_endpoint = ServerEndpoint(reactor, config['Port'])

    udp_protocol = UDPProtocol(config['UDPHost'], config['UDPPort'], replay) if args.udp else None
    server_endpoint.listen(ServerFactory(client_endpoint, udp_protocol, crypto, replay, args))

    print("[*] TCP Proxy is listening on {}:{}".format(server_endpoint.interface, server_endpoint.port))

    if udp_protocol is not None:
        udp_listener = reactor.listenUDP(config['UDPPort'], udp_protocol)
        udp_listener_host = udp_listener.getHost()

        print("[*] UDP Proxy is listening on {}:{}".format(udp_listener_host.host, udp_listener_host.port))

    reactor.addSystemEventTrigger('before', 'shutdown', onClose, udp_protocol)
    reactor.run()
