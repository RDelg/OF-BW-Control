#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, UserSwitch, OVSKernelSwitch
from mininet.link import Link
from mininet.cli import CLI
from mininet.log import setLogLevel

def topology():

    print '*** Creating network'
    net = Mininet(build=False, controller=None, autoSetMacs = True)

    print '*** Adding controller'
    c0 = net.addController( 'c0', controller=RemoteController, ip='127.0.0.1', port=6633 )

    print '*** Adding switches'
    s1 = net.addSwitch( 's1', listenPort=6674, protocols='OpenFlow13', cls=UserSwitch )
    for s in net.switches:
        print('%s ' % s.name),
    print " "

    print '*** Adding hosts'
    hosts = [ net.addHost( 'h%d' % n ) for n in xrange(1,4) ]

    for h in net.hosts:
        print('%s ' % h.name),
    print " "

    print '*** Adding links'
    for h in hosts1:
        net.addLink( s1, h )
        print ('(%s, %s) ' % (s1.name, h.name)),
    print " "

    print '*** Starting network'
    net.build()
    s1.start( [c0] )

    # print '*** Configuring hosts'
    for h in net.hosts:
        h.cmd('sudo ethtool -K %s-eth0 tso off' % h.name )

    # print '*** Running CLI'
    CLI( net )

    print '*** Stopping network'
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
