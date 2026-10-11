from scapy.all import sniff, IP, TCP

def handle(pkt):
    if IP in pkt and TCP in pkt:
        print(pkt[IP].src, "->", pkt[IP].dst, pkt[TCP].dport, pkt[TCP].flags)

sniff(iface="ens33", prn=handle, store=False)
