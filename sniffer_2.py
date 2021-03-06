import datetime
from subprocess import call
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def button_pressed_dash1():
  current_time = datetime.strftime(datetime.now(), '%Y-%m-%d %H:%M:%S')
  print 'Dash button pressed at ' + current_time
  call(["echo", "So we can also run shell commands. Hmmm... :)"])
  #call(["ssh -i " + BastionHost + " avineshwar@access.hpi.nyc -v"])
  call(["pwd"])

def udp_filter(pkt):
  options = pkt[DHCP].options
  for option in options:
    if isinstance(option, tuple):
      if 'requested_addr' in option:
        # we've found the IP address, which means its the second and final UDP request, so we can trigger our action
        mac_to_action[pkt.src]()
        break


mac_to_action = {'44:65:0d:8d:82:2a' : button_pressed_dash1}
mac_id_list = list(mac_to_action.keys())

print "Waiting for a button press..."
sniff(prn=udp_filter, store=0, filter="udp", lfilter=lambda d: d.src in mac_id_list)

if __name__ == "__main__":
  main()
