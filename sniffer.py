from scapy.all import *
def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
    #if 1==1:
    if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
      if pkt[ARP].hwsrc == '44:65:0d:8d:82:2a': # Pushed!
        print "Pushed my button. I can take some actions!"
      #elif pkt[ARP].hwsrc == '10:ae:60:00:4d:f3': # Elements
      #  print "Pushed Elements"
      else:
        print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

print sniff(prn=arp_display, filter="arp", store=0, count=10)
