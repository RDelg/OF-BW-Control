#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, UserSwitch, OVSKernelSwitch
from mininet.link import Link
from mininet.cli import CLI
from mininet.log import setLogLevel

def topology():

    # Create a network.
    net = Mininet(build=False, controller=None, autoSetMacs = True)

    # Creating controller
    c0 = net.addController( 'c0', controller=RemoteController, ip='127.0.0.1', port=6633 )

    # Creating switches
    s1 = net.addSwitch( 's1', listenPort=6673, protocols='OpenFlow13', cls=OVSKernelSwitch, failMode='standalone' )
    s2 = net.addSwitch( 's2', listenPort=6674, protocols='OpenFlow13', cls=UserSwitch )

    # Creating hosts
    hosts1 = [ net.addHost( 'h%d' % n ) for n in xrange(1,4) ]
    hosts2 = [ net.addHost( 'h%d' % n ) for n in xrange(4,7) ]

    # Creating links
    for h in hosts1:
        net.addLink( s1, h )
    for h in hosts2:
        net.addLink( s2, h )
    net.addLink( s1, s2 )

    # Starting network
    net.build()
    s1.start( [] )
    s2.start( [c0] )

    # Configuring hosts
    for h in hosts1:
        h.cmd('sudo ethtool -K %s-eth0 tso off' % h.name )
    for h in hosts2:
        h.cmd('sudo ethtool -K %s-eth0 tso off' % h.name )

    # Running CLI
    CLI( net )

    # Stopping network
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
