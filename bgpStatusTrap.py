#!/usr/bin/env python
# Notification Originator (TRAP)
import re
import time
import os
import sys
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp
from pyasn1.codec.ber import encoder
from pysnmp.proto import api
from pysnmp.smi import builder 
from os import stat
from os.path import abspath
from stat import ST_SIZE
from optparse import OptionParser

#SNMP Variables
snmpHostIp = '172.16.130.1'
verID = api.protoVersion2c
communityString = 'public'
# What log file to watch 
file = '/var/log/messages'
# What line in the log to match on 
expression = '.*(BGP).*'
# What information to pass to the external scipt or app call
match = '.*(BGP).*'

def startScript():
	child_pid = os.fork()
	if child_pid != 0:
		print 'Process %d spawned' % child_pid
	else:
		tail = LogTail(file, expression, match)
		tail.tail()

class LogTail:
	def __init__(self, logfile, expression, match):
		self.expression = expression
		self.match = match
		self.logfile = abspath(logfile)
		self.f = open(self.logfile,"r")
		file_len = stat(self.logfile)[ST_SIZE]
		self.f.seek(file_len)
		self.pos = self.f.tell()
	def _reset(self):
		self.f.close()
		self.f = open(self.logfile, "r")
		self.pos = self.f.tell()
	# Look for new entries in the log file
	def tail(self):
		while 1:
			self.pos = self.f.tell()
			line = self.f.readline()
			if not line:
				if stat(self.logfile)[ST_SIZE] < self.pos:
					self._reset()
				else:
					time.sleep(1)
					self.f.seek(self.pos)
			else:
				# Look for a matching line
				if re.match(self.expression, line, re.M|re.I):
					# Split out each word in the line
					words = re.findall(r'\w+', line)
					# Look for the passing argument/s contained in the line
					for current_word in words:
						#print(current_word)
						if re.match(self.match, current_word, re.M|re.I):
							pMod = api.protoModules[verID]
							# We matched, now send a log
							try:
								syslogIndex = words.index( 'ADJCHANGE' )
								print( syslogIndex )
								if words[syslogIndex + 15] == "Established":
									print('Established')
									bgpNbrUp = BgpNbrStateChange(
										1,
										(1, 3, 6, 1, 2, 1, 15, 3, 1, 14, int(words[syslogIndex + 2]), int(words[syslogIndex + 3]), int(words[syslogIndex + 4]), int(words[syslogIndex + 5])),
										(1, 3, 6, 1, 2, 1, 15, 3, 1, 2, int(words[syslogIndex + 2]), int(words[syslogIndex + 3]), int(words[syslogIndex + 4]), int(words[syslogIndex + 5])),
										pMod.Integer(6)
										)
									bgpNbrUp.sendTrap(pMod)
								elif words[syslogIndex + 15] == 'Idle':
									print('Idle')
									bgpNbrDown = BgpNbrStateChange(
										2,
										(1, 3, 6, 1, 2, 1, 15, 3, 1, 14, int(words[syslogIndex + 2]), int(words[syslogIndex + 3]), int(words[syslogIndex + 4]), int(words[syslogIndex + 5])),
										(1, 3, 6, 1, 2, 1, 15, 3, 1, 2, int(words[syslogIndex + 2]), int(words[syslogIndex + 3]), int(words[syslogIndex + 4]), int(words[syslogIndex + 5])),
										pMod.Integer(1)
										)
									bgpNbrDown.sendTrap(pMod)
							except ValueError as e:
								# Do not print an error if we see other syslogs.
								if str(e) != '\'ADJCHANGE\' is not in list':
									print( e )
																
class BgpNbrStateChange:
	#Setup the Trap
	def __init__(self, bgpEstOrBackTrans, bgpPeerLastErrIP, bgpPeerStateIP, bgpPeerState):
		self.bgpEstOrBackTrans = bgpEstOrBackTrans
		self.bgpPeerLastErrIP = bgpPeerLastErrIP
		self.bgpPeerStateIP = bgpPeerStateIP
		self.bgpPeerState = bgpPeerState
	
	#Send the Trap
	def sendTrap(self, pMod):
		self.pMod = pMod
		sysUpTime = (1,3,6,1,2,1,1,3,0)
		_zeroTime = self.pMod.TimeTicks(0)
		self.varBinds = (
				(sysUpTime, _zeroTime),
				#bgpNbrStateChange
				((1 ,3, 6, 1, 6, 3, 1, 1, 4, 1, 0), pMod.ObjectIdentifier((1, 3, 6, 1, 2, 1, 15, 7, 1))),
				#bgpPeerLastError 
				( self.bgpPeerLastErrIP, pMod.OctetString( [ 4,0 ] ) ),
				#bgpPeerState 
				( self.bgpPeerStateIP, self.bgpPeerState ),
				)
		sendOspfNbrStateChangeTrap = v2cTrap(self.varBinds, self.pMod)
		sendOspfNbrStateChangeTrap.sendTrap()

class v2cTrap:
	def __init__(self, varBinds, pMod):
		self.varBinds = varBinds
		self.pMod = pMod
				
	def sendTrap(self):
		
		# Build PDU
		trapPDU =  self.pMod.TrapPDU()
		self.pMod.apiTrapPDU.setDefaults(trapPDU)
		
		self.pMod.apiTrapPDU.setVarBinds(trapPDU, self.varBinds)
			
		# Build message
		trapMsg = self.pMod.Message()
		self.pMod.apiMessage.setDefaults(trapMsg)
		self.pMod.apiMessage.setCommunity(trapMsg, communityString )
		self.pMod.apiMessage.setPDU(trapMsg, trapPDU)
		
		transportDispatcher = AsynsockDispatcher()
		transportDispatcher.registerTransport(
			udp.domainName, udp.UdpSocketTransport().openClientMode()
			)
		transportDispatcher.sendMessage(
			encoder.encode(trapMsg), udp.domainName, ( snmpHostIp, 162 )
			)
		transportDispatcher.runDispatcher()
		transportDispatcher.closeDispatcher()


if __name__ == "__main__":
    startScript()
