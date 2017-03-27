from scapy.all import *
def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
    if pkt[ARP].hwsrc == '44:65:0d:8d:82:2a': # Pushed!
        print "Pushed my button. I can take some actions!"
    else:
        print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

print sniff(prn=arp_display, filter="arp", store=0, count=2)
