sudo ovs-ofctl -O OpenFlow13 add-meter unix:/tmp/s1 meter=1,kbps,band=type=drop,rate=15000
sudo ovs-ofctl -O OpenFlow13 add-meter unix:/tmp/s1 meter=2,kbps,band=type=drop,rate=30000
sudo ovs-ofctl -O OpenFlow13 add-meter unix:/tmp/s1 meter=3,kbps,band=type=drop,rate=20000

sudo ovs-ofctl -O OpenFlow13 add-flow unix:/tmp/s1 table=0,priority=1,dl_type=0x0806,arp_tpa=10.0.0.1,action=output=1
sudo ovs-ofctl -O OpenFlow13 add-flow unix:/tmp/s1 table=0,priority=1,dl_type=0x0806,arp_tpa=10.0.0.2,action=output=2
sudo ovs-ofctl -O OpenFlow13 add-flow unix:/tmp/s1 table=0,priority=1,dl_type=0x0806,arp_tpa=10.0.0.3,action=output=3

sudo ovs-ofctl -O OpenFlow13 add-flow unix:/tmp/s1 table=0,priority=1,dl_src=00:00:00:00:00:01,action=meter:1,goto_table:1
sudo ovs-ofctl -O OpenFlow13 add-flow unix:/tmp/s1 table=0,priority=1,dl_src=00:00:00:00:00:02,action=meter:2,goto_table:1
sudo ovs-ofctl -O OpenFlow13 add-flow unix:/tmp/s1 table=0,priority=1,dl_src=00:00:00:00:00:03,action=meter:3,goto_table:1

sudo ovs-ofctl -O OpenFlow13 add-flow unix:/tmp/s1 table=1,priority=1,dl_dst=00:00:00:00:00:01,action=output:1
sudo ovs-ofctl -O OpenFlow13 add-flow unix:/tmp/s1 table=1,priority=1,dl_dst=00:00:00:00:00:02,action=output:2
sudo ovs-ofctl -O OpenFlow13 add-flow unix:/tmp/s1 table=1,priority=1,dl_dst=00:00:00:00:00:03,action=output:3