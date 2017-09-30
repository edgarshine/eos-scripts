#!/usr/bin/env python
#
# aclsync.py v1.1
# Requires minimum EOS version of 4.15.0F
# Arista Networks, Inc.
# Written by: Richard Whitney
# rw@arista.com
# 4/12/16
#

import jsonrpclib, socket, sys, syslog
from jsonrpclib import Server


#----------------Main-----------------#

if __name__ == "__main__":    
    syslog.openlog( 'ACLSYNC', 0, syslog.LOG_LOCAL4 )
    if len (sys.argv ) != 5:
        print "Usage: ./<script> remote-switch account password acl-name"
        sys.exit( 1 )
    if len ( sys.argv ) == 5:
        remotehost = sys.argv[ 1 ]
        account =  sys.argv[ 2 ]
        password =  sys.argv[ 3 ]
        acl = sys.argv[4]
        url = "https://%s:%s@%s/command-api" % ( account, password, remotehost )
        remoteSwitch = Server( url )
        localSwitch = Server( "unix:/var/run/command-api.sock")
    
    # Get the acl from the local switch
    try:
        aclConfig = localSwitch.runCmds( 1, [ "enable",
                                              "show running-config" ] )[ 1 ][ 'cmds' ][ "ip access-list " + acl ][ 'cmds' ]
    except socket.error as e:
        print "Could not open local connection, exiting"
        syslog.syslog( '%ACLSYNC-6-LOG: ERROR - Could not open local connection' )
        sys.exit( 1 )
    except:
        print "Error, exiting"
        syslog.syslog( '%ACLSYNC-6-LOG: ERROR - exiting' )
        sys.exit( 1 )
    
    # Build the temp config
    configCmdTemp = [ "enable", "configure session temp", "no ip access-list " + acl, "ip access-list " + acl ]
    for line in sorted( aclConfig, key=lambda key:int( key[:3] ) ):
        configCmdTemp.append( line )
    configCmdTemp.append( "abort" )
    configCmdTemp.append( "abort" )
    commandSuccess = False

    # Send the configuration to a temporary session on the remote switch to test
    try:
        response = remoteSwitch.runCmds( 1, configCmdTemp )
        commandSuccess = True
    except jsonrpclib.jsonrpc.ProtocolError as e:
        print "Configuration session error, exiting"
        syslog.syslog( '%ACLSYNC-6-LOG: ERROR - Configuration error' )
        sys.exit( 1 )
    except socket.error as e:
        print "Could not open remote connection, exiting"
        syslog.syslog( '%ACLSYNC-6-LOG: ERROR - Could not open remote connection' )
        sys.exit( 1 )
    except:
        print "Error, exiting"
        syslog.syslog( '%ACLSYNC-6-LOG: ERROR - exiting' )
        sys.exit( 1 )
    
    # Build the tested config
    if commandSuccess:
        configCmd = [ "enable", "configure", "no ip access-list " + acl, "ip access-list " + acl ]
        for line in sorted( aclConfig, key=lambda key:int( key[:3] ) ):
            configCmd.append( line )
    
    # Send the configuration to remote switch
    try:
        response = remoteSwitch.runCmds( 1, configCmd )
        commandSuccess = True
    except jsonrpclib.jsonrpc.ProtocolError as e:
        print "Configuration error, exiting"
        syslog.syslog( '%ACLSYNC-6-LOG: ERROR - Configuration error' )
        sys.exit( 1 )
    except socket.error as e:
        print "Could not open remote connection, exiting"
        syslog.syslog( '%ACLSYNC-6-LOG: ERROR - Could not open remote connection' )
        sys.exit( 1 )
    if commandSuccess:
        print "ACL Sync was successful"
        syslog.syslog( '%ACLSYNC-6-LOG: NOTICE - ACL Sync was successful' )
