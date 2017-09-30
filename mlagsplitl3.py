#!/usr/bin/python
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#  - Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#  - Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#  - Neither the name of Arista Networks nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ARISTA NETWORKS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
#    Version 1.0 2/17/2015
#    Written by: 
#       Teren Sapp and Richard Whitney, Arista Networks
#
#    Revision history:
#       1.0 - Initial version tested on EOS 4.14.4F 

"""
   DESCRIPTION
     MLAG Split Brain tool checks the MLAG state and reachability of 
     remote peer and disables all MLAG client port-channels and vlan
     interfaces. If the MLAG state comes back, then all ports are
     then re-enabled. This script should only be place on ONE of the 
     MLAG peers.

   INSTALLATION
     In order to install this script:
       - Copy the script to /mnt/flash
       - Enable the Command API interface:

            management api http-commands
              no shutdown

       - Change USERNAME, PASSWORD and ALIVEADDRESS
         (remote peer reachable address, such as lo0) at the
         top of the script to the ones appropriate for your installation.
         
   USAGE

      - Script should be configured to be managed as a daemon:
      
           daemon mlagsplitl3
             command /mnt/flash/mlagsplitl3.py
        
   COMPATIBILITY
      This has been tested with EOS 4.14.x using eAPI

   LIMITATIONS
      None known
"""
import time
import subprocess
import json
from jsonrpclib import Server

#----------------------------------------------------------------
# Configuration section
#----------------------------------------------------------------
SWITCH = '127.0.0.1'
USERNAME = 'admin'
PASSWORD = 'admin'
ALIVEADDRESS = '4.4.4.4'
#----------------------------------------------------------------

urlString = "https://{}:{}@{}/command-api".format(USERNAME,PASSWORD,SWITCH)
switchReq = Server( urlString )

def enableint():
  try:
    mlagints = switchReq.runCmds( 1, ["show mlag interfaces"] )
    for interfaces in mlagints[0]['interfaces']:
      try:
        enableintvlan = switchReq.runCmds( 1, ["enable", "configure", "interface vlan" + interfaces, "no shutdown", "end"] )
      except: 
        print "Error enabling MLAG vlan interface"
      try:
        enableintpo = switchReq.runCmds( 1, ["enable", "configure", "interface port-channel" + interfaces, "no shutdown", "end"] )
      except: 
        print "Error enabling MLAG client interface"
  except:
    print "Could not get MLAG clinet interfaces"

def disableint():
  try:
    mlagints = switchReq.runCmds( 1, ["show mlag interfaces"] )
    for interfaces in mlagints[0]['interfaces']:
      try:
        shutintvlan = switchReq.runCmds( 1, ["enable", "configure", "interface vlan" + interfaces, "shutdown", "end"] )
      except:     
        print "Error disabling MLAG vlan interface"
      try:
        shutintpo = switchReq.runCmds( 1, ["enable", "configure", "interface port-channel" + interfaces, "shutdown", "end"] )
      except:     
        print "Error disabling MLAG client interface"
  except:
    print "Could not get MLAG clinet interfaces"

def main():
  while(1):
    try:
      showmlag = switchReq.runCmds( 1, ["show mlag detail"] )
    except:
      print "Could not communicate with switch. Please check eAPI configuration and verify URL"
      print "URL: " + urlString
      quit()

    if showmlag[0]['state'] == 'disabled':
      print "MLAG Not Enabled"
      quit()

    try:
      negstatus = showmlag[0]["negStatus"]
      peeraddress = showmlag[0]["peerAddress"]

    except:
      print "Could not get necessary MLAG information"
      quit()

    pingpeer = subprocess.call(["ping","-c1","-w1","-q",peeraddress], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if negstatus != 'connected' or pingpeer != 0:
      pingalive = subprocess.call(["ping","-c1","-w1","-q",ALIVEADDRESS], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      if pingalive == 0:
        print "Lost peer link and remote system is alive, disabling all MLAG client ports and routed interfaces"
        disableint()
      if pingalive != 0:
        print "Lost peer link and remote system is dead, enabling all MLAG client ports and routed interfaces"
        enableint()
    else:
      print "MLAG is now connected, verifyng ports are enabled"
      enableint()

    time.sleep(5)

if __name__ == '__main__':
    main()
