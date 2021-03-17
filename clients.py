from scapy.all import *

BSSID_FILE = "/Desktop/Python/bssid.txt"

def manf(bss):
    file = open(BSSID_FILE, 'r')
    for line in file.read().splitlines():
        if line.split("~")[0][7] == bss[7]:
            return line.split("~")[1].rstrip("\n")
    return "unknown"

def pkt_callback(pkt):
    if pkt.haslayer(Dot11Beacon):
        bss = pkt.getlayer(Dot11).addr2.upper()
        if bss not in APs:
            APs.append(bss)

    elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
        # This means it's data frame.
        sn = pkt.getlayer(Dot11).addr2.upper()
        rc = pkt.getlayer(Dot11).addr1.upper()

        if sn in APs:
            print "AP (%s) [%s] > STA (%s) [%s]" % (sn, manf(sn), rc, manf(rc))
        elif rc in APs:
            print "AP (%s) [%s] < STA (%s) [%s]" % (rc, manf(rc), sn, manf(sn))

if __name__ == "__main__":
    sniff(iface="wlxc83a35c2e0b8", prn=pkt_callback)
