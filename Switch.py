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
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.src_to_meter = {}
        self.meter_to_src = {}
        self.n_meter = {}
        self.port_to_meter = {}
        self.deleted_flows = {}
        with open('/home/mininet/Rene/subs.json') as data_file:    
            self.subs = json.load(data_file)
        self.max_rate = 200000
        self.default_rate = 5000
        self.rate_request = {}
        self.rate_allocated = {}
        self.rate_used = {}
        self.rate_used_mod = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.sleep = 5
        self.port_speed = {}
        self.port_prev = {}
        self.meter_speed = {}
        self.meter_prev = {}
        
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
        self.meter_to_src.setdefault(dpid, {})
        self.rate_request.setdefault(dpid, {})
        self.rate_allocated.setdefault(dpid, {})
        self.rate_used.setdefault(dpid, {})
        self.rate_used_mod.setdefault(dpid, {})
        self.deleted_flows.setdefault(dpid, {})

        # add resubmit flow
        inst = [parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, 
                                instructions=inst, table_id=0)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                # Datapath's dictionaries for BW measurement
                self.port_speed[datapath.id] = {}
                self.port_prev[datapath.id] = {}
                self.meter_speed[datapath.id] = {}
                self.meter_prev[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                # Deleting datapath's dictionaries
                del self.port_speed[datapath.id]
                del self.port_prev[datapath.id]
                del self.meter_speed[datapath.id]
                del self.meter_prev[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep)

    def _get_speed(self, now, pre, period):
        return 8*((now-pre)/(period*1000000.0))

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPMeterStatsRequest(datapath, 0, ofproto.OFPM_ALL)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.logger.info('datapath         port     '
                         'rx Mbps '
                         'tx Mbps ')
        self.logger.info('---------------- -------- '
                         '------- '
                         '------- ')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.port_speed[dpid].setdefault(stat.port_no, {})

            try:
                self.port_speed[dpid][stat.port_no]['rx'] = self._get_speed(stat.rx_bytes, self.port_prev[dpid][stat.port_no]['rx'], self.sleep)
                self.port_speed[dpid][stat.port_no]['tx'] = self._get_speed(stat.tx_bytes, self.port_prev[dpid][stat.port_no]['tx'], self.sleep)
                self.logger.info('%016x %8x %5.2f %5.2f',
                                ev.msg.datapath.id, stat.port_no,
                                self.port_speed[dpid][stat.port_no]['rx'],
                                self.port_speed[dpid][stat.port_no]['tx'])
            except:
                self.logger.info('No stats')

            self.port_prev[dpid].setdefault(stat.port_no, {})
            self.port_prev[dpid][stat.port_no]['rx'] = stat.rx_bytes
            self.port_prev[dpid][stat.port_no]['tx'] = stat.tx_bytes

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.logger.info('datapath         meter_id   Mbps  ')
        self.logger.info('---------------- -------- --------')

        for stat in sorted(body, key=attrgetter('meter_id')):
            try:
                self.meter_speed[dpid][stat.meter_id] = self._get_speed(stat.byte_in_count, self.meter_prev[dpid][stat.meter_id], self.sleep)
                self.logger.info("%016x %08x %5.2f",
                                dpid, stat.meter_id, 
                                self.meter_speed[dpid][stat.meter_id])
                if stat.meter_id in self.meter_to_src[dpid]:
                    src = self.meter_to_src[dpid][stat.meter_id]
                    port = self.mac_to_port[dpid][src]
                    self.rate_used[dpid].setdefault(port, {})
                    self.rate_used_mod[dpid].setdefault(port, {})
                    self.rate_used[dpid][port][src] = self.meter_speed[dpid][stat.meter_id]
                    if (self.rate_used[dpid][port][src] >= int(self.rate_allocated[dpid][port][src]*0.7) 
                        and (self.rate_allocated[dpid][port][src] != self.rate_request[dpid][port][src])):
                        self.rate_used_mod[dpid][port][src] = int(self.rate_used[dpid][port][src]*1.5)
                        thread = threading.Thread(target=self.mod_port_meters, args=(dpid, port, ))
                        thread.start()
                    else:
                        self.rate_used_mod[dpid][port][src] = self.rate_used[dpid][port][src]
            except:
                self.logger.info('No stats')
            self.meter_prev[dpid][stat.meter_id] = stat.byte_in_count

    def mod_port_meters(self, dpid, in_port):
        self.logger.debug('Datapath: %s modifying port %d meters', dpid, port)
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        cmd     = ofproto.OFPMC_MODIFY
        prev_allocated = self.rate_allocated[dpid].get(in_port, {})
        self.rate_allocated[dpid][in_port] = self.rate_control(self.max_rate, self.rate_request[dpid][in_port], self.rate_used_mod[dpid][in_port])
        for src in self.rate_allocated[dpid][in_port]:
            if prev_allocated.get(src, 0) != self.rate_allocated[dpid][in_port][src]:
                rate    = self.rate_allocated[dpid][in_port][src]
                match   = parser.OFPMatch(in_port=self.mac_to_port[dpid][src], eth_src=src)
                self.mod_meter_entry(datapath, cmd, src_to_meter[dpid][src], rate)

    def mod_meter_entry(self, dp, cmd, meter_id, rate, burst_size = 0):
        rate = int(rate)
        meter_id = int(meter_id)
        burst_size = int(burst_size)
        flags = dp.ofproto.OFPMF_KBPS
        bands = [dp.ofproto_parser.OFPMeterBandDrop(rate, burst_size)]
        meter_mod = dp.ofproto_parser.OFPMeterMod(dp, cmd, flags, meter_id, bands)
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

    def add_qos(self, datapath, priority, match, meter_id, rate, idle_to=0):
        self.add_qos_meter(datapath, meter_id, rate)
        self.add_qos_flow(datapath, priority, match, meter_id, idle_to)
        self.logger.debug('qos added')

    def add_qos_meter(self, datapath, meter_id, rate):
        ofproto = datapath.ofproto
        cmd     = ofproto.OFPMC_ADD
        self.mod_meter_entry(datapath, cmd, meter_id, rate)

    def add_qos_flow(self, datapath, priority, match, meter_id, idle_to):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionMeter(meter_id), parser.OFPInstructionGotoTable(1)]
        mod     = parser.OFPFlowMod(datapath=datapath, priority=priority, flags=ofproto.OFPFF_SEND_FLOW_REM,
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
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if src not in self.port_to_meter[dpid]:
            self.logger.debug('adding qos to port: %s', in_port)
            self.n_meter[dpid] += 1
            self.port_to_meter[dpid][src] = self.n_meter[dpid]
            match   = parser.OFPMatch(in_port=in_port)
            # run thread to avoid performance decreasing
            thread  = threading.Thread(target=self.add_qos, 
                                    args=(datapath, 1, match, 
                                    self.n_meter[dpid], 
                                    self.default_rate, ))
            thread.start()

        # search if there is a rule for the src
        if src in self.subs:
            # search if there is a existing meter already
            if src not in self.src_to_meter[dpid]:
                # recalculate rate allocated to in_port
                self.rate_request[dpid][in_port][src] = int(self.subs[src])
                prev_allocated = self.rate_allocated[dpid].get(in_port, {})
                self.rate_allocated[dpid][in_port] = self.rate_control(self.max_rate, self.rate_request[dpid][in_port], self.rate_used_mod[dpid].get(in_port, {}))
                self.logger.debug('requested %s', self.rate_request[dpid][in_port])
                self.logger.debug('used %s', self.rate_used_mod[dpid].get(in_port, {}))
                self.logger.debug('allocated %s', self.rate_allocated[dpid][in_port])
                # add meter and flow
                self.logger.debug('adding qos to src: %s', src)
                self.n_meter[dpid] += 1
                self.src_to_meter[dpid][src] = self.n_meter[dpid]
                self.meter_to_src[dpid][self.n_meter[dpid]] = src
                rate    = self.rate_allocated[dpid][in_port][src]
                match   = parser.OFPMatch(in_port=in_port, eth_src=src)
                # run thread to avoid performance decreasing
                thread  = threading.Thread(target=self.add_qos, args=(datapath, 2, match, self.n_meter[dpid], rate, ),
                                            kwargs=dict(idle_to=30))
                thread.start()
                # modify the others in_port's meters 
                for src2 in self.rate_allocated[dpid][in_port]:
                    if src != src2 and  prev_allocated.get(src2, 0) != self.rate_allocated[dpid][in_port][src2]:
                        self.logger.debug('modifying qos to src: %s', src2)
                        cmd     = ofproto.OFPMC_MODIFY
                        rate    = self.rate_allocated[dpid][in_port][src2]
                        match   = parser.OFPMatch(in_port=self.mac_to_port[dpid][src2], eth_src=src2)
                        # run thread to avoid performance decreasing
                        thread  = threading.Thread(target=self.mod_meter_entry, args=(datapath, cmd, src_to_meter[dpid][src2], rate))
                        thread.start()

            elif src in self.src_to_meter[dpid] and self.deleted_flows[dpid].get(src, False) == True:
                # rewrite qos flow
                self.deleted_flows[dpid][src] = False
                match = parser.OFPMatch(in_port=in_port, eth_src=src)
                self.add_qos_flow(datapath, 2, match, self.src_to_meter[dpid][src], idle_to=30)

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
        src = msg.match.get('eth_src', 0)
        self.deleted_flows[dpid][src] = True
        self.logger.debug("Matches eth_src: %s in_port: %s", src, msg.match.get('in_port', 0))

    def rate_control(self, bandwith, requested, used):
        allocated = {}
        totalRequested = sum(requested.values())
        totalUsed = sum(used.values())
        partOfWhole = 0
        leftOver = 0
        if totalRequested < bandwith:
            allocated = requested
            leftOver = bandwith - totalRequested
        else:
            requested = requested.copy()
            for src in requested:
                tmp = int((used.get(src, requested[src]*0.5)*1.5))
                if tmp < requested[src]:
                    requested[src] = tmp
                if requested[src] == 0:
                    requested[src] = 5
            partOfWhole = int(bandwith/len(requested))
            leftOver = bandwith % len(requested)
            for src in requested:
                if partOfWhole > requested[src]:
                    allocated[src] = requested[src]
                    leftOver += partOfWhole - requested[src]
                else:
                    allocated[src] = partOfWhole
            while leftOver > 0:
                stillNeed = 0
                for src in requested:
                    if (requested[src] - allocated[src]) > 0:
                        stillNeed += 1
                if stillNeed < leftOver:
                    for src in requested:
                        if (requested[src] - allocated[src]) > 0:
                             allocated[src]+=1
                             leftOver-=1
                else:
                    maxDiff = 0
                    for src in requested:
                        if requested[src] - allocated[src] > maxDiff:
                            maxDiff = requested[src] - allocated[src]
                            tempI = src
                    allocated[tempI] += 1
                    leftOver -= 1
        return allocated
