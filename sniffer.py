from scapy.all import*
def handler(packet):
    print(packet.summary())
sniff(iface="enp0s3",prn=handler,store=0)
