# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import threading
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_meter = {}
        self.n_meter = {}
        self.port_to_meter = {}
        with open('/home/mininet/Rene/subs.json') as data_file:    
            self.subs = json.load(data_file)
        self.default_rate = 5000
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_MAX)]  
        match = parser.OFPMatch()
        # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                   ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 1)

        dpid = datapath.id
        self.mac_to_meter.setdefault(dpid, {})
        self.n_meter.setdefault(dpid, 0)
        self.port_to_meter.setdefault(dpid, {})

        # add resubmit flow
        inst = [parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, 
                                instructions=inst, table_id=0)
        datapath.send_msg(mod)


    def mod_meter_entry(self, dp, flow, cmd):
        flags_convert = {'KBPS': dp.ofproto.OFPMF_KBPS,
                         'PKTPS': dp.ofproto.OFPMF_PKTPS,
                         'BURST': dp.ofproto.OFPMF_BURST,
                         'STATS': dp.ofproto.OFPMF_STATS}
        flow_flags = flow.get('flags')
        if not isinstance(flow_flags, list):
            flow_flags = [flow_flags]
        flags = 0
        for flag in flow_flags:
            flags |= flags_convert.get(flag, 0)
        if not flags:
            LOG.error('Unknown flags: %s', flow.get('flags'))
        meter_id = int(flow.get('meter_id', 0))
        bands = []
        for band in flow.get('bands', []):
            band_type = band.get('type')
            rate = int(band.get('rate', 0))
            burst_size = int(band.get('burst_size', 0))
            if band_type == 'DROP':
                bands.append(
                    dp.ofproto_parser.OFPMeterBandDrop(rate, burst_size))
            elif band_type == 'DSCP_REMARK':
                prec_level = int(band.get('prec_level', 0))
                bands.append(
                    dp.ofproto_parser.OFPMeterBandDscpRemark(
                        rate, burst_size, prec_level))
            elif band_type == 'EXPERIMENTER':
                experimenter = int(band.get('experimenter', 0))
                bands.append(
                    dp.ofproto_parser.OFPMeterBandExperimenter(
                        rate, burst_size, experimenter))
            else:
                LOG.error('Unknown band type: %s', band_type)
        meter_mod = dp.ofproto_parser.OFPMeterMod(
            dp, cmd, flags, meter_id, bands)
        dp.send_msg(meter_mod)


    def add_flow(self, datapath, priority, match, actions, table, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table)
        datapath.send_msg(mod)


    def add_qos(self, datapath, priority, match, meter_id, flow, cmd):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.mod_meter_entry(datapath, flow, cmd)
        inst = [parser.OFPInstructionMeter(meter_id), parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, 
                                instructions=inst, table_id=0)
        datapath.send_msg(mod)
        self.logger.debug('qos added')


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if not src in self.port_to_meter[dpid]:
            self.logger.debug('adding qos to port: %s', in_port)
            self.n_meter[dpid] += 1
            self.port_to_meter[dpid][src] = self.n_meter[dpid]
            flow = {'meter_id': self.n_meter[dpid], 
                    'flags': 'KBPS', 
                    'bands':[{'type':'DROP', 'rate': self.default_rate}]}
            cmd = ofproto.OFPMC_ADD
            match = parser.OFPMatch(in_port=in_port)
            thread =  threading.Thread(target=self.add_qos, args=(datapath, 1,
                                        match, self.n_meter[dpid], flow, cmd, ))
            thread.start()

        if not src in self.mac_to_meter[dpid]:
            self.logger.debug('adding qos to src: %s', src)
            # searching rule
            if src in self.subs:
                rate = self.subs[src]
                self.n_meter[dpid] += 1
                self.mac_to_meter[dpid][src] = self.n_meter[dpid]
                self.logger.debug('Rate rule: %s Kbps', rate)
                # adding meter and flow
                cmd = ofproto.OFPMC_ADD
                match = parser.OFPMatch(in_port=in_port, eth_src=src)
                flow = {'meter_id': self.mac_to_meter[dpid][src], 
                        'flags': 'KBPS', 
                        'bands':[{'type':'DROP', 'rate': rate}]}
                thread =  threading.Thread(target=self.add_qos, args=(datapath, 2,
                                            match, self.n_meter[dpid], flow, cmd, ))
                thread.start()
            else:
                self.mac_to_meter[dpid][src] = 'Default'
                self.logger.debug('Default rate')

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, 1, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions, 1)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)