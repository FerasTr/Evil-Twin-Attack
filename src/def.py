# from: https://community.spiceworks.com/topic/581682-how-can-i-detect-and-possibly-block-deauth-packets
from scapy.all import *
import sys

counter = 0


def sniffReq(p):
    global counter
    if p.haslayer(Dot11Deauth):
        counter += 1
        print(
            p.sprintf(
                "------------------------------------------------------------------------------------------"
            )
        )
    if counter >= 10:
        if p.addr1 == "ff:ff:ff:ff:ff:ff":
            print(
                p.sprintf(
                    "Deauth Found from AP [%Dot11.addr2%] Client [%Dot11.addr1%], Reason [%Dot11Deauth.reason%]"
                )
            )
        else:
            print(
                p.sprintf(
                    "Deauth Found from AP [%Dot11.addr1%] Client [%Dot11.addr2%], Reason [%Dot11Deauth.reason%]"
                )
            )
        sys.exit()


sniff(iface="wlx34080432263f", prn=sniffReq)
