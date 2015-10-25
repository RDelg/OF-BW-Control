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
        self.src_to_meter = {}
        self.n_meter = {}
        self.port_to_meter = {}
        with open('/home/mininet/Rene/subs.json') as data_file:    
            self.subs = json.load(data_file)
        self.max_rate = 20000
        self.default_rate = 5000
        self.rate_request = {}
        self.rate_allocated = {}
        self.src_port = {}
        self.datapaths = {}
        

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
        self.n_meter.setdefault(dpid, 0)
        self.src_to_meter.setdefault(dpid, {})
        self.port_to_meter.setdefault(dpid, {})
        self.rate_request.setdefault(dpid, {})
        self.rate_allocated.setdefault(dpid, {})
        self.src_port.setdefault(dpid, {})
        self.datapaths[dpid] = datapath

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


    def add_flow(self, datapath, priority, match, actions, table, idle_to=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table,
                                    idle_timeout = idle_to)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table,
                                    idle_timeout = idle_to)
        datapath.send_msg(mod)


    def add_qos(self, datapath, priority, match, meter_id, flow, cmd, idle_to=0):
        self.add_qos_meter(datapath, flow, cmd)
        self.add_qos_flow(datapath, priority, match, meter_id, idle_to)
        self.logger.debug('qos added')


    def add_qos_meter(self, datapath, flow, cmd):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.mod_meter_entry(datapath, flow, cmd)

    def add_qos_flow(self, datapath, priority, match, meter_id, idle_to):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionMeter(meter_id), parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                match=match, instructions=inst, table_id=0, idle_timeout=idle_to)
        datapath.send_msg(mod)


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
        self.rate_request[dpid].setdefault(in_port, {})
        self.src_port[dpid].setdefault(in_port, [])
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if not src in self.port_to_meter[dpid]:
            self.logger.debug('adding qos to port: %s', in_port)
            # self.rate_request[dpid][in_port]['Default'] = self.default_rate
            self.n_meter[dpid] += 1
            self.port_to_meter[dpid][src] = self.n_meter[dpid]
            cmd = ofproto.OFPMC_ADD
            flow = {'meter_id': self.n_meter[dpid], 
                    'flags': 'KBPS', 
                    'bands':[{'type':'DROP', 'rate': self.default_rate}]}
            match = parser.OFPMatch(in_port=in_port)
            thread =  threading.Thread(target=self.add_qos, args=(datapath, 1,
                                        match, self.n_meter[dpid], flow, cmd, ))
            thread.start()

        # search rule
        if not src in self.src_port[dpid][in_port]:
            self.src_port[dpid][in_port].append(src)
            if src in self.subs:
                self.rate_request[dpid][in_port][src] = int(self.subs[src])
                try:
                    prev_allocated = self.rate_allocated[dpid][in_port]
                except:
                    prev_allocated = {}
                self.rate_allocated[dpid][in_port] = self.rate_control(self.max_rate, self.rate_request[dpid][in_port])
                if not src in self.src_to_meter[dpid]:
                    # add meter and flow
                    self.logger.debug('adding qos to src: %s', src)
                    cmd = ofproto.OFPMC_ADD
                    self.n_meter[dpid] += 1
                    self.src_to_meter[dpid][src] = self.n_meter[dpid]
                else:
                    self.logger.debug('A: modifying qos to src: %s', src)
                    cmd = ofproto.OFPMC_MODIFY
                rate = self.rate_allocated[dpid][in_port][src]
                match = parser.OFPMatch(in_port=in_port, eth_src=src)
                flow = {'meter_id': self.src_to_meter[dpid][src], 
                        'flags': 'KBPS', 
                        'bands':[{'type':'DROP', 'rate': rate}]}
                thread =  threading.Thread(target=self.add_qos, args=(datapath, 2,
                                            match, self.n_meter[dpid], flow, cmd, ),
                                            kwargs=dict(idle_to=30))
                thread.start()
                for src2 in self.rate_allocated[dpid][in_port]:
                    if src != src2 and self.rate_allocated[dpid][in_port][src2] != prev_allocated.get(src2):
                        cmd = ofproto.OFPMC_MODIFY
                        rate = self.rate_allocated[dpid][in_port][src]
                        match = parser.OFPMatch(in_port=in_port, eth_src=src)
                        flow = {'meter_id': self.src_to_meter[dpid][src], 
                                'flags': 'KBPS', 
                                'bands':[{'type':'DROP', 'rate': rate}]}
                        self.logger.debug('B: modifying qos to src: %s', src2)
                        thread =  threading.Thread(target=self.mod_meter_entry, args=(datapath, flow, cmd ))
                        thread.start()

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
                self.add_flow(datapath, 1, match, actions, 1, idle_to=30, buffer_id=msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions, 1, idle_to=30)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        dpid = dp.id

        src = msg.match.get('eth_src', None)
        del self.src_to_meter[dpid][src]

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.debug('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, msg.match)
        self.logger.debug("Matches eth_src: %s in_port: %s", msg.match.get('eth_src', 0), msg.match.get('in_port', 0))


    def rate_control(self, bandwith, request):
        allocated = {}
        totalRequest = sum(request.values())
        partOfWhole = 0
        leftOver = 0
        # print "Requested %d of %d maximum bandwith" %(totalRequest, bandwith)
        if totalRequest < bandwith:
            allocated = request
            leftOver = bandwith - totalRequest
        else:
            partOfWhole = int(bandwith/len(request))
            leftOver = bandwith % len(request)
            for src in request:
                if partOfWhole > request[src]:
                    allocated[src] = request[src]
                    leftOver += partOfWhole - request[src]
                else:
                    allocated[src] = partOfWhole
            while leftOver > 0:
                stillNeed = 0
                for src in request:
                    if (request[src] - allocated[src]) > 0:
                        stillNeed += 1
                if stillNeed < leftOver:
                    for src in request:
                        if (request[src] - allocated[src]) > 0:
                             allocated[src]+=1
                             leftOver-=1
                else:
                    maxDiff = 0
                    for src in request:
                        if request[src] - allocated[src] > maxDiff:
                            maxDiff = request[src] - allocated[src]
                            tempI = src
                    allocated[tempI] += 1
                    leftOver -= 1
        return allocated
