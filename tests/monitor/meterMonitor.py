from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from time import time

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
        self.time_prev = {}
        self.output = open('monitor.csv', 'w')

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
                self.time_prev[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                # Deleting datapath's dictionaries
                del self.port_speed[datapath.id]
                del self.port_prev[datapath.id]
                del self.meter_speed[datapath.id]
                del self.meter_prev[datapath.id]
                del self.time_prev[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep)

    def _get_speed(self, now, pre, period):
        return 8*((now-pre)/(period*1000.0))

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPMeterStatsRequest(datapath, 0, ofproto.OFPM_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.logger.info('datapath         meter_id   kbps  ')
        self.logger.info('---------------- -------- --------')
        self.output.write('%d,%d' % (time(), dpid))
        for stat in sorted(body, key=attrgetter('meter_id')):
            if stat.meter_id in self.time_prev[dpid]:
                sleep = float(stat.duration_sec) + (stat.duration_nsec / 10.0**9) - self.time_prev[dpid][stat.meter_id]
            else:
                sleep = self.sleep
            self.time_prev[dpid][stat.meter_id] = float(stat.duration_sec) + (stat.duration_nsec / 10.0**9)

            self.meter_speed[dpid][stat.meter_id] = self._get_speed(stat.byte_in_count, self.meter_prev[dpid].get(stat.meter_id, stat.byte_in_count), sleep)
            self.meter_prev[dpid][stat.meter_id] = stat.byte_in_count
            self.logger.info('%016x %08x %6.1f',dpid, stat.meter_id, self.meter_speed[dpid].get(stat.meter_id, 0))
            self.output.write(',%f' % self.meter_speed[dpid].get(stat.meter_id, 0))
        self.output.write('\n')


