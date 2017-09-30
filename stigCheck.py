#!/usr/bin/env python
#
# STIG Check v1.9
# Date: 4/15/2016
# Author: Rich Whitney
#         Arista Networks, inc.
#         rw@arista.com
#
# Replace with "1" for debug messages
DEBUG = 0

from collections import defaultdict
from jsonrpclib import Server
import re, sys, syslog

# Port security maximum MACs
portSecurityMax = 1

#Define functions

def ospfv3Check():
    if DEBUG == 1: print "Verifying OSPFv3 is configured securely\n"
    ospf3Intf = switch.runCmds( 1, [ "show ipv6 ospf interface" ] )[ 0 ][ 'vrfs' ]
    for vrf in ospf3Intf.keys():
        instList = ospf3Intf[vrf][u'instList']
        ospfInstances = instList.keys()
        assert len(ospfInstances) == 1 # should be exactly one OSPF instance in each VRF
        perIntfState = instList[ospfInstances[0]]['indices']
        for intf, state in perIntfState.iteritems():
            noAuth = True
            if DEBUG == 1: print "    Checking", intf, "\n"
            if state.has_key(u"authentication"):
                pass
            else:
                if DEBUG == 1: print "    FINDING: Interface", intf, "does not have authentication configured, checking for area authentication:" 
                ospfCommand = "show ipv6 ospf vrf " + vrf
                ospfVrfArea = switch.runCmds( 1, [ ospfCommand ] )[ 0 ][ 'vrfs' ][ vrf ][ 'instList' ]
                instList = ospfVrfArea.keys()
                assert len( instList ) == 1 # should be exactly one OSPF instance in each VRFa
                instance = ospfVrfArea[ instList[0] ][ 'areaList' ][ state[ 'area'] ].keys()
                for line in instance:
                    if line == "areaAuthTypeInformation":
                        noAuth = False
                        break
                if noAuth == True:
                    if DEBUG == 1: print "        ADDITIONAL FINDING: Area", state[ 'area' ], "in vrf", state[ 'vrf' ], "DOES NOT have authentication configured\n"
                    syslog.syslog ( '%FINDING-6-LOG: OSPFv3 Authentication needs to be configured on interface ' + intf + ' or area ' + state[ 'area' ] + ' in vrf ' + state[ 'vrf' ] )
                else: 
                    if DEBUG == 1: print "        Area", state [ 'area' ], "in vrf", state[ 'vrf' ], "DOES have authentication configured\n" 

def snmpCheck():
    if DEBUG == 1: print "Verifying SNMP\n"
    rawSnmpGroupConfig = switch.runCmds( 1, [ 'show snmp group' ], 'text' )
    rawSnmpConfig = switch.runCmds( 1, [ 'show snmp' ], 'text' )
    rawSnmpCommunity = switch.runCmds( 1, [ 'show snmp community' ], 'text' )
    snmpNumGroupsRegex = re.compile( r'Group name' )
    snmpDisabledRegex = re.compile( r'SNMP agent disabled' )
    snmpSecRegex = re.compile( r'Group name     : \S+\nSecurity model : v3 priv' )
    snmpDisabledGroup = re.findall( snmpDisabledRegex, rawSnmpConfig[ 0 ][ 'output' ] )
    if snmpDisabledGroup:
        if DEBUG == 1: print "    FINDING: SNMP needs to be enabled\n"    
        syslog.syslog( '%FINDING-6-LOG: SNMP needs to be enabled' )    
    else:
        if rawSnmpCommunity[ 0 ][ 'output' ]:
            if DEBUG == 1: print "    NOTICE: SNMP using both authentication and privacy is recommended but is not confiugured for all instances\n"
            syslog.syslog( '%NOTICE-6-LOG: SNMP using both authentication and privacy is recommended but is not confiugured for all instances' )
        else:
            snmpNumGroups = len( re.findall( snmpNumGroupsRegex, rawSnmpGroupConfig[ 0 ][ 'output' ] ) )
            if snmpNumGroups:
                snmpSecGroup = re.findall( snmpSecRegex, rawSnmpGroupConfig[ 0 ][ 'output' ] )
                if len( snmpSecGroup ) != snmpNumGroups:
                    if DEBUG == 1: print "    NOTICE: SNMP using both authentication and privacy is recommended but is not confiugured for all instances\n"
                    syslog.syslog( '%NOTICE-6-LOG: SNMP using both authentication and privacy is recommended but is not confiugured for all instances' )

def routedIntfCheck():
    if DEBUG == 1: print "Verifying routed interface settings\n"
    intfIpVerDict = dict()
    needsIpv4Acl = []
    needsIpv6Acl = []
    needsPimAcl = []
    needsMcBoundaryAcl = []
    needsipv6ndra = []
    ipv4Regex = re.compile( r'^ip address' )
    ipv6Regex = re.compile( r'^ipv6 address' )
    vlanIntfRegex = re.compile( r'^interface Vlan[0-9]' )
    ethIntfRegex = re.compile( r'interface Ethernet[0-9]' )
    ipv4AclRegex = re.compile( r'ip access-group' )
    ipv6AclRegex = re.compile( r'ipv6 access-group' )
    pimAclRegex = re.compile( r'ip pim neighbor-filter' )
    mcBoundaryAclRegex = re.compile( r'ip multicast boundary' )
    for line in runConfig:
        vlanIntfGroup = re.match( vlanIntfRegex, line )
        if vlanIntfGroup:
            intfConfig = runConfig[ line ][ 'cmds' ]
            intfIpVerDict[ line ] = dict()
            intfIpVerDict[ line ][ 'ipv4' ] = False
            intfIpVerDict[ line ][ 'ipv6' ] = False
            for ipv4ConfigLine in intfConfig:
                ipv4Group = re.match( ipv4Regex, ipv4ConfigLine )
                if ipv4Group:
                    intfIpVerDict[ line ][ 'ipv4' ] = True
            for ipv6ConfigLine in intfConfig:
                ipv6Group = re.match( ipv6Regex, ipv6ConfigLine )
                if ipv6Group:
                            intfIpVerDict[ line ][ 'ipv6' ] = True
        ethIntfGroup = re.match( ethIntfRegex, line )
        if ethIntfGroup:
            intfConfig = runConfig[ line ][ 'cmds' ]
            for configLine in intfConfig:
                switchport = 1
                if configLine == 'no switchport':
                    switchport = 0 
                if switchport == 0:
                    intfIpVerDict[ line ] = dict()
                    intfIpVerDict[ line ][ 'ipv4' ] = False
                    intfIpVerDict[ line ][ 'ipv6' ] = False
                    for ipv4ConfigLine in intfConfig:
                        ipv4Group = re.match( ipv4Regex, ipv4ConfigLine )
                        if ipv4Group:
                            intfIpVerDict[ line ][ 'ipv4' ] = True
                    for ipv6ConfigLine in intfConfig:
                        ipv6Group = re.match( ipv6Regex, ipv6ConfigLine )
                        if ipv6Group:
                            intfIpVerDict[ line ][ 'ipv6' ] = True    
    for line in intfIpVerDict.keys():
        intfConfig = runConfig[ line ][ 'cmds' ]
        if intfIpVerDict[ line ][ 'ipv4' ] == True:
            pimChecked = 0
            aclApplied = 0
            pimAclApplied = 0
            mcBoundaryAclApplied = 0
            intfConfig = runConfig[ line ][ 'cmds' ]
            for configLine in intfConfig:
                aclGroup = re.match( ipv4AclRegex, configLine )
                if aclGroup:
                    aclApplied = 1
                if (configLine == 'ip pim sparse-mode' or configLine == 'ip pim bidirectional') and pimChecked == 0:
                    pimChecked = 1
                    for configLine in intfConfig:
                        pimAclGroup = re.match( pimAclRegex, configLine )
                        if pimAclGroup:
                            pimAclApplied = 1
                        mcBoundaryAclGroup = re.match( mcBoundaryAclRegex, configLine )
                        if mcBoundaryAclGroup: 
                            mcBoundaryAclApplied = 1
            if aclApplied == 0:
                needsIpv4Acl.append ( line )
            if pimAclApplied == 0:
                needsPimAcl.append ( line )
            if mcBoundaryAclApplied == 0:
                needsMcBoundaryAcl.append ( line )
    if  len( needsIpv4Acl ) > 0:
        if DEBUG == 1: print "    FINDING: IPv4 ACLs need to be applied to these interfaces:"
        for line in needsIpv4Acl:
            if DEBUG == 1: print "    %s" % line
            syslog.syslog( '%FINDING-6-LOG: An IPv4 ACL needs to be applied to interface: ' + line )
        if DEBUG == 1: print "\n"
    if  len( needsPimAcl ) > 0:
        if DEBUG == 1: print "    FINDING: PIM neighbor ACLs need to be applied to these interfaces:"
        for line in needsPimAcl:
            if DEBUG == 1: print "    %s" % line
            syslog.syslog( '%FINDING-6-LOG: A PIM neighbor ACL needs to be applies to this interface: ' + line )
        if DEBUG == 1: print "\n"
    if  len( needsMcBoundaryAcl ) > 0:
        if DEBUG == 1: print "    FINDING: A multicast boundary ACL needs be applied to these interfaces:"
        for line in needsMcBoundaryAcl:
            if DEBUG == 1: print "    %s" % line
            syslog.syslog( '%FINDING-6-LOG: A multicast boundary ACL needs to be applies to this interface: ' + line )
        if DEBUG == 1: print "\n"
    for line in intfIpVerDict.keys():
        intfConfig = runConfig[ line ][ 'cmds' ]
        if intfIpVerDict[ line ][ 'ipv6' ] == True:
            aclApplied = 0
            ipv6ndra = 0
            intfConfig = runConfig[ line ][ 'cmds' ]
            for configLine in intfConfig:
                aclGroup = re.match( ipv6AclRegex, configLine )
                if aclGroup:
                    aclApplied = 1
                if configLine == 'ipv6 nd ra hop-limit 32':
                    ipv6ndra = 1
            if aclApplied == 0:
                needsIpv6Acl.append ( line )
            if ipv6ndra == 0:
                needsipv6ndra.append ( line )
            
    if  len( needsIpv6Acl ) > 0:
        if DEBUG == 1: print "    FINDING: IPv6 ACLs need to be applied to these interfaces:"
        for line in needsIpv6Acl:
            if DEBUG == 1: print "    %s" % line
            syslog.syslog( '%FINDING-6-LOG: An IPv6 ACL needs to be applied to this interface: ' + line )
        if DEBUG == 1: print "\n"

    if  len( needsipv6ndra ) > 0:
        if DEBUG == 1: print "    FINDING: IPv6 ND RA Hop count limit of 32 needs to be configured on these interfaces:"
        for line in needsipv6ndra:
            if DEBUG == 1: print "    %s" % line
            syslog.syslog( '%FINDING-6-LOG: An IPv6 ND RA Hop count limit of 32 needs to be configured on this interface: ' + line )
        if DEBUG == 1: print "\n"
    

    for line in intfIpVerDict.keys():
        intfConfig = runConfig[ line ][ 'cmds' ]
         
  

def vlan1Check():
    if DEBUG == 1: print "Verifying VLAN 1 is suspended\n"
    vlan1Status = switch.runCmds( 1, [ "show vlan" ] )[ 0 ][ 'vlans' ][ '1' ][ 'status' ] 
    if vlan1Status == 'active':
        if DEBUG == 1: print "    FINDING: VLAN 1 needs to be suspended\n"    
        syslog.syslog( '%FINDING-6-LOG: VLAN 1 needs to be suspended' )    

def logCheck():
    if DEBUG == 1: print "Verifying remote syslog\n"
    loggingRegex = re.compile( r'^logging host|^logging vrf .* host' )
    for line in runConfig:
        loggingMatchGroup = re.match( loggingRegex, line )
        if loggingMatchGroup:
            break
    else:
        if DEBUG == 1: print "    FINDING: Remote syslogging needs to be configured\n"
        syslog.syslog( '%FINDING-6-LOG: Remote syslogging needs to be configured' )

def ntpCheck():
    if DEBUG == 1: print "Verifying NTP\n"
    ntpRegex = re.compile( r'^ntp server' )
    for line in runConfig:
        ntpMatchGroup = re.match( ntpRegex, line )
        if ntpMatchGroup:
            break
    else:
        if DEBUG == 1: print "    FINDING: NTP needs to be configured\n"        
        syslog.syslog( '%FINDING-6-LOG: NTP needs to be configured' )        

def radiusCheck():
    if DEBUG == 1: print "Verifying RADIUS\n"
    radiusRegex = re.compile( r'^radius-server' )
    for line in runConfig:
        radiusMatchGroup = re.match ( radiusRegex, line )
        if radiusMatchGroup:
            break
    else:
        if DEBUG == 1: print "    FINDING: Radius needs to be configured\n"
        syslog.syslog( '%FINDING-6-LOG: Radius needs to be configured' )

def aaaCheck():
    if DEBUG == 1: print "Verifying AAA\n"
    aaa1Regex = re.compile( r'^aaa authentication login default group radius local' )
    aaa2Regex = re.compile( r'^aaa authentication login console group radius local' )
    aaa3Regex = re.compile( r'^aaa authentication dot1x default group radius' )
    aaa4Regex = re.compile( r'^aaa authentication policy on-success log' )
    aaa5Regex = re.compile( r'^aaa authentication policy on-failure log' )
    aaa6Regex = re.compile( r'^aaa authorization console' )
    aaa7Regex = re.compile( r'^aaa authorization commands all default local' )
    aaa8Regex = re.compile( r'^aaa accounting exec default start-stop group radius logging' )
    aaa9Regex = re.compile( r'^aaa accounting system default start-stop group radius logging' )
    aaa10Regex = re.compile( r'^aaa accounting commands all default start-stop logging group radius' )
    aaa11Regex = re.compile( r'^aaa authorization exec default local' )
    requiredAaa = set([ 'aaa authentication login default group radius local', 
                        'aaa authentication login console group radius local', 
                        'aaa authentication dot1x default group radius',
                        'aaa authentication policy on-success log',
                        'aaa authentication policy on-failure log',
                        'aaa authorization console',
                        'aaa authorization commands all default local',
                        'aaa accounting exec default start-stop group radius logging',
                        'aaa accounting system default start-stop group radius logging',
                        'aaa accounting commands all default start-stop logging group radius',
                        'aaa authorization exec default local' ] )
    for line in runConfig:
        aaa1MatchGroup = re.match( aaa1Regex, line )
        if aaa1MatchGroup:
            requiredAaa.remove( 'aaa authentication login default group radius local' )
        aaa2MatchGroup = re.match( aaa2Regex, line )
        if aaa2MatchGroup:
            requiredAaa.remove( 'aaa authentication login console group radius local' )
        aaa3MatchGroup = re.match( aaa3Regex, line )
        if aaa3MatchGroup:
            requiredAaa.remove( 'aaa authentication dot1x default group radius' )
        aaa4MatchGroup = re.match( aaa4Regex, line )
        if aaa4MatchGroup:
            requiredAaa.remove( 'aaa authentication policy on-success log' )
        aaa5MatchGroup = re.match( aaa5Regex, line )
        if aaa5MatchGroup:
            requiredAaa.remove( 'aaa authentication policy on-failure log' )
        aaa6MatchGroup = re.match( aaa6Regex, line )
        if aaa6MatchGroup:
            requiredAaa.remove( 'aaa authorization console' )
        aaa7MatchGroup = re.match( aaa7Regex, line )
        if aaa7MatchGroup:
            requiredAaa.remove( 'aaa authorization commands all default local' )
        aaa8MatchGroup = re.match( aaa8Regex, line )
        if aaa8MatchGroup:
            requiredAaa.remove( 'aaa accounting exec default start-stop group radius logging' )
        aaa9MatchGroup = re.match( aaa9Regex, line )
        if aaa9MatchGroup:
            requiredAaa.remove( 'aaa accounting system default start-stop group radius logging' )
        aaa10MatchGroup = re.match( aaa10Regex, line )
        if aaa10MatchGroup:
            requiredAaa.remove( 'aaa accounting commands all default start-stop logging group radius' )
        aaa11MatchGroup = re.match( aaa11Regex, line )
        if aaa11MatchGroup:
            requiredAaa.remove( 'aaa authorization exec default local' )
    if len(requiredAaa) > 0:
        if DEBUG == 1: print "    FINDING: AAA Configuration is missing the following items:"
        for line in requiredAaa:
            if DEBUG == 1: print "    " + line
            syslog.syslog( '%FINDING-6-LOG: The following is missing from the AAA configuration: ' + line )
        if DEBUG == 1: print "\n"

def rootCheck():
    if DEBUG == 1: print "Verifying root account is disabled\n"
    rootMatchRegex = re.compile( r'^aaa root secret' )
    for line in runConfig:
        rootMatchGroup = re.match ( rootMatchRegex, line )
        if rootMatchGroup:
            if DEBUG == 1: print "    FINDING: The root user needs to be disabled\n"
            syslog.syslog( '%FINDING-6-LOG: The root user needs to be disabled' )

def mgmtVrfCheck():
    if DEBUG == 1: print "Verifying management interface is in a VRF\n"
    vrfMatchRegex = re.compile( r'^vrf forwarding' )
    for intfConfig in runConfig[ 'interface Management1' ][ 'cmds' ]:
       if re.match( vrfMatchRegex, intfConfig ):
           break
    else:
        if DEBUG == 1: print "    FINDING: Interface Management1 needs to be configured in a management VRF\n"             
        syslog.syslog( '%FINDING-6-LOG: Interface Management1 needs to be configured in a management VRF' )             
        
def isisCheck():
    if DEBUG == 1: print "Verifying ISIS is not configured\n"
    isisMatchRegex = re.compile( r'^router isis' )
    for isisConfig in runConfig:
       if re.match( isisMatchRegex, isisConfig ):
           if DEBUG == 1: print "    FINDING: ISIS is configured but must be removed\n"             
           syslog.syslog( '%FINDING-6-LOG: ISIS is configured but must be removed' )            

def ripCheck():
    if DEBUG == 1: print "Verifying RIP is not configured\n"
    ripMatchRegex = re.compile( r'^router rip' )
    for ripConfig in runConfig:
       if re.match( ripMatchRegex, ripConfig ):
           if DEBUG == 1: print "    FINDING: RIP is configured but must be removed\n"             
           syslog.syslog( '%FINDING-6-LOG: RIP is configured but must be removed' )             

def ospfCheck():
    if DEBUG == 1: print "Verifying OSPF is configured securely\n"
    ospfMatchRegex = re.compile( r'^router ospf.*$' )
    ospfVrfRegex = re.compile( r'^router ospf.*(vrf .*$)' )
    ospfIntMatchRegex = re.compile( r'(.*) is [up|down]' )
    ospfIntDigestMatchRegex = re.compile( r'Message-digest authentication' )
    ospfProcessList = []
    ospfMessageDigestList = []
    for line in runConfig:
       ospfMatchGroup = re.match( ospfMatchRegex, line )
       if ospfMatchGroup:
           ospfProcessList.append ( line )
    for line in ospfProcessList:
            vrfName = re.findall( ospfVrfRegex, line )
            if vrfName:
                if DEBUG == 1: print "    Checking %s" % line
                rawConfig = switch.runCmds( 1, [ 'show ip ospf interface ' + vrfName[0] ], 'text' )
                ospfInt = re.findall( ospfIntMatchRegex, rawConfig[ 0 ][ 'output' ] )
                if DEBUG == 1:
                    for int in ospfInt:
                        print "        %s" % int
                    print "\n"
                for int in ospfInt:
                    ospfCommand = "show ip ospf interface %s %s" % int, vrfName
                    rawOspfInt = switch.runCmds( 1, [ ospfCommand ], 'text' )
                    ospfIntDigest = re.search( ospfIntDigestMatchRegex, rawOspfInt[ 0 ][ 'output' ] )
                    if ospfIntDigest is None:
                        ospfMessageDigestList.append( int )
            else:
                if DEBUG == 1: print "    Checking %s" % line
                rawConfig = switch.runCmds( 1, ['show ip ospf interface'], 'text' )
                ospfInt = re.findall( ospfIntMatchRegex, rawConfig[ 0 ][ 'output' ] )
                if DEBUG == 1:
                    for int in ospfInt:
                        print "        %s" % int
                    print "\n"
                for int in ospfInt:
                    ospfCommand = "show ip ospf interface %s" % int
                    rawOspfInt = switch.runCmds( 1, [ ospfCommand ], 'text' )
                    ospfIntDigest = re.search( ospfIntDigestMatchRegex, rawOspfInt[ 0 ][ 'output' ] )
                    if ospfIntDigest is None:
                        ospfMessageDigestList.append( int )
    if len( ospfMessageDigestList ) > 0:
        if DEBUG == 1: print "    FINDING: OSPF interfaces that require message-digest authentication:"
        for noDigestInt in ospfMessageDigestList:
            if DEBUG == 1: print "        " + noDigestInt
            syslog.syslog( '%FINDING-6-LOG: OSPF interface requires message-digest authentication: ' + noDigestInt )
        if DEBUG == 1: print "\n"

def bgpCheck():
    if DEBUG == 1: print "Verifying BGP is configured securely\n"
    bgpMatchRegex = re.compile( r'^router bgp.*')
    bgpIntMatchRegex = re.compile( r'BGP neighbor is (.*?),' )
    rawConfig = switch.runCmds( 1, [ 'show ip bgp neighbors' ], 'text' )
    bgpNeighborsList = []
    for line in runConfig:
        bgpMatchGroup = re.match( bgpMatchRegex, line )
        if bgpMatchGroup:
            bgpProcess = bgpMatchGroup.group( 0 )
            bgpInt = re.findall( bgpIntMatchRegex, rawConfig[ 0 ][ 'output' ] )
            for int in bgpInt:
                command = "neighbor %s password" % int
                for line in runConfig[ bgpProcess ][ 'cmds' ]:
                    bgpNeighborAuth = re.match( command, line )
                    if bgpNeighborAuth:
                        break
                else:
                    bgpNeighborsList.append( int )
    if len( bgpNeighborsList ) > 0:
        if DEBUG == 1: print "    FINDING: BGP Neighbors that require authentication:"
        for noBgpAuth in bgpNeighborsList:
            if DEBUG == 1: print "    %s" % noBgpAuth
            syslog.syslog( '%FINDING-6-LOG: BGP neighbor that requires authentication: ' + noBgpAuth )
        if DEBUG == 1: print "\n"

def bgpTtlAclCheck():
    cpExists = 0
    if DEBUG == 1: print "Verifying BGP TTL acl is applied\n"
    controlPlaneRegex = re.compile( r'control-plane$' )
    bgpTtlAclRegex = re.compile( r'.*eq bgp ttl eq 255 log' )
    cpAclRegex = re.compile( r'ip access-group (.*?) [a-z]'  )
    cpAclList = []
    for line in runConfig:
        cpConfig = re.match( controlPlaneRegex, line )
        if cpConfig: 
            cpExists = 1
            for line in runConfig[ 'control-plane' ][ 'cmds' ]:
                appliedAcl = re.findall( cpAclRegex, line )
                if appliedAcl:
                    cpAclList.append( appliedAcl[ 0 ] ) 
                    for acl in cpAclList:
                        aclName = "ip access-list %s" % acl
                        for line in runConfig[ aclName ][ 'cmds' ]:
                            ttlEntry = re.match( bgpTtlAclRegex, line )
                            if ttlEntry:
                                break 
                        else:
                            if DEBUG == 1: print "    FINDING: The control-plane ACL \"%s\" requires a BGP TTL entry\n" % acl
                            syslog.syslog( '%FINDING-6-LOG: This control-plane ACL requires a bgp TTL entry: ' + acl )
    if cpExists == 0:
        if DEBUG == 1: print "    FINDING: The default control-plane ACL is applied and does not have a BGP TTL entry\n"
        syslog.syslog( '%FINDING-6-LOG: The default control-plane ACL is applied and does not have a BGP TTL entry' )

def bannerCheck():
    if DEBUG == 1: print "Verifying login banner is configured\n"
    bannerRegex = re.compile( r'^banner login' )
    for line in runConfig:
       if re.match( bannerRegex, line ):
           return None
    if DEBUG == 1: print "    FINDING: A login banner needs to be configured\n"
    syslog.syslog( '%FINDING-6-LOG: A login banner needs to be configured' )

def mgmtSecCheck():
    if DEBUG == 1: print "Verifying management security parameters are set\n"
    mgmtSecRegex = re.compile( r'^management security' )
    passMinRegex = re.compile( r'^password minimum length 15' )
    entropyRegex = re.compile( r'^entropy source hardware' )
    requiredMgmtSec = set ( [ 'password minimum length 15', 
                             'entropy source hardware' ] )
    for line in runConfig:
        mgmtSecGroup = re.match ( mgmtSecRegex, line )
        if mgmtSecGroup:
            for line in runConfig[ 'management security' ][ 'cmds' ]:
                passMinGroup = re.match( passMinRegex, line )
                if passMinGroup:
                    requiredMgmtSec.remove( 'password minimum length 15' )
                entropyGroup = re.match( entropyRegex, line )
                if entropyGroup:
                    requiredMgmtSec.remove( 'entropy source hardware' )
            if len(requiredMgmtSec) > 0:
                if DEBUG == 1: print "    FINDING: Management security configuration is missing the following items:"
                for line in requiredMgmtSec:
                    if DEBUG == 1: print "    " + line
                    syslog.syslog( '%FINDING-6-LOG: Management security configuration is missing: ' + line )
                if DEBUG == 1: print "\n"
            return None
    if DEBUG == 1: print "    FINDING: Management security configuration is missing the following:"
    for line in requiredMgmtSec:
        if DEBUG == 1: print "    " + line 
        syslog.syslog( '%FINDING-6-LOG: Management security configuration is missing: ' + line )
    if DEBUG == 1: print "\n"

def mgmtSshCheck():
    if DEBUG == 1: print "Verifying SSH security parameters are set\n"
    mgmtSshRegex = re.compile( r'^management ssh' )
    idleTimeRegex = re.compile( r'^idle-timeout 10' )
    fipsRegex = re.compile( r'^fips restrictions' )
    requiredMgmtSsh = set ( [ 'idle-timeout 10', 
                             'fips restrictions' ] )
    for line in runConfig:
        mgmtSshGroup = re.match( mgmtSshRegex, line )
        if mgmtSshGroup:
            for line in runConfig['management ssh']['cmds']:
                idleTimeGroup = re.match( idleTimeRegex, line )
                if idleTimeGroup:
                    requiredMgmtSsh.remove( 'idle-timeout 10' )
                fipsGroup = re.match( fipsRegex, line )
                if fipsGroup:
                    requiredMgmtSsh.remove( 'fips restrictions' )
            if len(requiredMgmtSsh) > 0:
                if DEBUG == 1: print "    FINDING: Management ssh configuration is missing the following items:"
                for line in requiredMgmtSsh:
                     if DEBUG == 1: print "    " + line
                     syslog.syslog( '%FINDING-6-LOG: Management ssh configuration is missing: ' + line )
                if DEBUG == 1: print "\n"
            return None
    if DEBUG == 1: print "    FINDING: Management ssh configuration is missing the following:"
    for line in requiredMgmtSsh:
        if DEBUG == 1: print "    " + line
        syslog.syslog( '%FINDING-6-LOG: Management ssh configuration is missing: ' + line )
    if DEBUG == 1: print "\n"
   
def portSecCheck():
    if DEBUG == 1: print "Verifying that access ports are configured with port-security or dot1x\n"
    intfMatchRegex = re.compile( r'^interface Ethernet.*' )
    switchPortAccessRegex = re.compile( r'^switchport access' )
    portSecRegex = re.compile( r'^switchport port-security|dot1x' )
    accessIntfList = []
    for line in runConfig:
        intfMatchGroup = re.match( intfMatchRegex, line )
        if intfMatchGroup:
            intfName = intfMatchGroup.group( 0 )
            for switchPortLine1 in runConfig[ intfName ][ 'cmds' ]:
                if re.match( switchPortAccessRegex, switchPortLine1 ):
                   for switchPortLine2 in runConfig[ intfName ][ 'cmds' ]:
                       if re.match( portSecRegex, switchPortLine2 ):
                           break
                   else:
                       accessIntfList.append( intfName )
    if len( accessIntfList ) > 0:
        if DEBUG == 1: print "    FINDING: Switchports in access mode that require port-security or dot1x:"
        for intf in accessIntfList:
            if DEBUG == 1: print "    " + intf
            syslog.syslog( '%FINDING-6-LOG: Swtichport requires port-security or dot1x: ' + intf )
        if DEBUG == 1: print "\n"

#----------------Main-----------------#

if __name__ == "__main__":
    
    if len (sys.argv ) not in ( 1, 4 ):
        print "Usage: ./<script> hostname account password\nFor unix socket access: ./<script>"
        print "Use 'nopass' if account has no password"
        sys.exit( 1 )
    if len ( sys.argv ) == 1:
        switch = Server( "unix:/var/run/command-api.sock")
    if len ( sys.argv ) == 4: 
        hostname = sys.argv[ 1 ]
        account =  sys.argv[ 2 ]
        password =  sys.argv[ 3 ]
        if password == "nopass":
            password = ""
        url = "http://%s:%s@%s/command-api" % ( account, password, hostname )
        switch = Server( url )
    try:
        runConfig = switch.runCmds( 1, [ "enable",
                                         "show running-config" ] )[ 1 ][ 'cmds' ]
    except:
        print "Could not open connection, exiting"
        sys.exit( 1 )
    syslog.openlog( 'stigCheck', 0, syslog.LOG_LOCAL4 )

    if DEBUG == 1: print "\n-----STIG Check v1.4-----\n"

    # SNMP Check
    snmpCheck()
    
    # Routed interface check
    routedIntfCheck()

    # VLAN 1 Check
    vlan1Check()
 
    # Logging Check
    logCheck()

    # NTP Check
    ntpCheck()
 
    # RADIUS Check
    radiusCheck()
  
    # AAA Check
    aaaCheck()

    # Root user check
    rootCheck()

    # Management VRF Check for Management1 interface
    mgmtVrfCheck()

    # Check for ISIS configuration
    isisCheck()

    # Check for RIP configuration
    ripCheck()

    # Check OSPF for secure configuration
    ospfCheck()

    # Check OSPFv3 for secure configuration
    ospfv3Check()
 
    # Check BGP for secure configuration
    bgpCheck()
 
    # Check BGP TTL
    bgpTtlAclCheck()

    # Check management security
    mgmtSecCheck()

    # Check management ssh
    mgmtSshCheck()

    # Switch port-security or dot1x check
    portSecCheck()
