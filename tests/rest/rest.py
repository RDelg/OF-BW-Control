import json
import logging

from webob import Response
from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub


simple_switch_instance_name = 'simple_switch_api_app'

class SimpleSwitchRest13(SimpleSwitch13):

    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchRest13, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController, {simple_switch_instance_name : self})
        self.datapaths = {}
        self.lock = hub.Event()
        self.flows = []

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                self.mac_to_port[datapath.id]   = {}

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                del self.mac_to_port[datapath.id]

    def send_flow_request(self, datapath):
        self.logger.debug('send flow request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, 0, ofproto.OFPTT_ALL, ofproto.OFPP_ANY, ofproto.OFPG_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
    	msg = ev.msg
    	flows = []
    	for stat in ev.msg.body:
    		flows.append('table_id=%s '
		                 'duration_sec=%d duration_nsec=%d '
		                 'priority=%d '
		                 'idle_timeout=%d hard_timeout=%d flags=0x%04x '
		                 'cookie=%d packet_count=%d byte_count=%d '
		                 'match=%s instructions=%s' %
		                 (stat.table_id,
		                  stat.duration_sec, stat.duration_nsec,
		                  stat.priority,
		                  stat.idle_timeout, stat.hard_timeout, stat.flags,
		                  stat.cookie, stat.packet_count, stat.byte_count,
		                  stat.match, stat.instructions))
    	self.logger.debug('FlowStats: %s', flows)
    	self.flows = flows
    	self.lock.set()


class SimpleSwitchController(ControllerBase):

	def __init__(self, req, link, data, **config):
		super(SimpleSwitchController, self).__init__(req, link, data, **config)
		self.simpl_switch_spp = data[simple_switch_instance_name]

	@route('simpleswitch', '/mactable/{dpid}' , methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
	def list_mac_table(self, req, **kwargs):

		simple_switch = self.simpl_switch_spp
		dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

		if dpid not in simple_switch.mac_to_port:
			return Response(status=404)

		mac_table = simple_switch.mac_to_port.get(dpid, {})
		body = json.dumps(mac_table, indent=4, sort_keys=True)
		return Response(content_type='application/json', body=body)

	@route('simpleswitch', '/flows/{dpid}' , methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
	def list_flows(self, req, **kwargs):

		simple_switch = self.simpl_switch_spp
		dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
		dp = simple_switch.datapaths[dpid]
		simple_switch.send_flow_request(dp)
		simple_switch.lock.wait()
		body = json.dumps(simple_switch.flows, indent=4, sort_keys=True)
		return Response(content_type='application/json', body=body)


# 	flows = []
# 	    body = ev.msg.body
# 	    for stat in sorted(body, key=attrgetter('table_id')):
# 	    	flow = {'table_id': stat.table_id,
# 					'duration_sec': stat.duration_sec, 
# 					'duration_nsec': stat.duration_nsec,
# 					'priority': stat.priority,
# 					'idle_timeout': stat.idle_timeout,
# 					'hard_timeout': stat.hard_timeout, 
# 					'flags': stat.flags,
# 					'cookie': stat.cookie,
# 					'packet_count': stat.packet_count,
# 					'byte_count': stat.byte_count,
# 					'match': stat.match,
# 					'instructions': stat.instructions
# 	    			}
# 	    	flows.append(flow)