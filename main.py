import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="interface", help="Write the network interface")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[!] Please add an interface to proceed (like : python main.py -i en0), --help for more informations.")
    return options

def get_mac_address(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    ask_list = scapy.srp(packet, timeout = 1, verbose = False)[0]
    return ask_list[0][1].hwsrc

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet)

print("""
 ______     ______     ______      _____     ______     ______   ______     ______     ______   ______     ______    
/\  __ \   /\  == \   /\  == \    /\  __-.  /\  ___\   /\__  _\ /\  ___\   /\  ___\   /\__  _\ /\  __ \   /\  == \   
\ \  __ \  \ \  __<   \ \  _-/    \ \ \/\ \ \ \  __\   \/_/\ \/ \ \  __\   \ \ \____  \/_/\ \/ \ \ \/\ \  \ \  __<   
 \ \_\ \_\  \ \_\ \_\  \ \_\       \ \____-  \ \_____\    \ \_\  \ \_____\  \ \_____\    \ \_\  \ \_____\  \ \_\ \_\ 
  \/_/\/_/   \/_/ /_/   \/_/        \/____/   \/_____/     \/_/   \/_____/   \/_____/     \/_/   \/_____/   \/_/ /_/ 

[!] Waiting for arp spoofing attacks..                                                                                                                     
""")

def sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op:
        try:
            mac = get_mac_address(packet[scapy.ARP].psrc)
            res = packet[scapy.ARP].hwsrc
            if mac != res:
                print("[!] ARP spoofing detected ! Send the army !!")
        except IndexError: 
            pass

options = get_arguments()
sniffer(options.interface)