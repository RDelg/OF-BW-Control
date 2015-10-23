# from ryu.app import simple_switch_13
# class SimpleMonitor(simple_switch_13.SimpleSwitch13):

from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


class SimpleMonitor(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.sleep = 5
        self.port_speed = {}
        self.port_prev = {}
        self.meter_speed = {}
        self.meter_prev = {}

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
            # self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d', 
            #                  ev.msg.datapath.id, stat.port_no,
            #                  stat.rx_packets, stat.rx_bytes, stat.rx_errors,
            #                  stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            self.port_speed[dpid].setdefault(stat.port_no, {})
            # if not stat.port_no in self.port_speed[dpid]:
            #     self.port_speed[dpid][stat.port_no] = {}
            try:
                # self.logger.info('RX Bytes: %8d %8d', stat.rx_bytes, self.port_prev[stat.port_no]['rx'])
                self.port_speed[dpid][stat.port_no]['rx'] = self._get_speed(stat.rx_bytes, self.port_prev[dpid][stat.port_no]['rx'], self.sleep)
                self.port_speed[dpid][stat.port_no]['tx'] = self._get_speed(stat.tx_bytes, self.port_prev[dpid][stat.port_no]['tx'], self.sleep)
                self.logger.info('%016x %8x %5.2f %5.2f',
                                ev.msg.datapath.id, stat.port_no,
                                self.port_speed[dpid][stat.port_no]['rx'],
                                self.port_speed[dpid][stat.port_no]['tx'])
                # self.logger.info('%8x tx %.2f Mbps',stat.port_no,self.port_speed[dpid][stat.port_no]['tx'])
            except:
                self.logger.info('No stats')
            self.port_prev[dpid].setdefault(stat.port_no, {})
            # if not stat.port_no in self.port_prev[dpid]:
            #     self.port_prev[dpid][stat.port_no] = {}
            self.port_prev[dpid][stat.port_no]['rx'] = stat.rx_bytes
            self.port_prev[dpid][stat.port_no]['tx'] = stat.tx_bytes

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.logger.info('datapath         meter_id   Mbps  ')
        self.logger.info('---------------- -------- --------')
        # meter = []
        for stat in sorted(body, key=attrgetter('meter_id')):
            try:
                self.meter_speed[dpid][stat.meter_id] = self._get_speed(stat.byte_in_count, self.meter_prev[dpid][stat.meter_id], self.sleep)
                self.logger.info("%016x %08x %5.2f",
                                ev.msg.datapath.id, stat.meter_id, 
                                self.meter_speed[dpid][stat.meter_id])
            except:
                self.logger.info('No stats')
            self.meter_prev[dpid][stat.meter_id] = stat.byte_in_count
            # meters.append('meter_id=0x%08x len=%d flow_count=%d '
            #               'packet_in_count=%d byte_in_count=%d '
            #               'duration_sec=%d duration_nsec=%d '
            #               'band_stats=%s' %
            #               (stat.meter_id, stat.len, stat.flow_count,
            #                stat.packet_in_count, stat.byte_in_count,
            #                stat.duration_sec, stat.duration_nsec,
            #                stat.band_stats))
        # self.logger.debug('MeterStats: %s', meters)
