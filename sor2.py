import dpkt
import socket
import sys
lines = set()

print("Converting binary to ASCII.")
def printPcap(pcap):
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            #print(f"source ipv4: {src}") - More CPU usage which slows down the file.
            #lines.add(f"iptables -A INPUT -s {src} -j DROP\n") - If Malicious then you can use this, don't forget to remove your IP from the list.
            lines.add(f"{src}\n")

        except:
            pass

def main():
    f = open(sys.argv[1],"rb") # [r]ead [b]inary
    pcap = dpkt.pcap.Reader(f)
    printPcap(pcap)


if __name__ == "__main__":
    main()

print(f"Writing results to: {sys.argv[2]}.")

for line in lines: # Filter, sets don't allow duplicate lines.
  f = open(sys.argv[2],"a")
  f.write(line)

sys.exit()

# python3 sor2.py <input> <output>
# python3 sor2.py icmp.pcap icmp.txt