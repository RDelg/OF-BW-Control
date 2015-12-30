import json
import logging

# from ryu.app import simple_switch_13
from Switch import SimpleSwitch13
from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib

simple_switch_instance_name = 'simple_switch_api_app'

class SimpleSwitchRest13(SimpleSwitch13):

    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchRest13, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController, {simple_switch_instance_name : self})


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

	@route('simpleswitch', '/bandwidth/{dpid}' , methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
	def list_bandwidth_table(self, req, **kwargs):

		simple_switch = self.simpl_switch_spp
		dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

		if dpid not in simple_switch.mac_to_port:
			return Response(status=404)

		bandwidth = {}
		bandwidth['Requested'] = simple_switch.rate_request.get(dpid, {})
		bandwidth['Allocated'] = simple_switch.rate_allocated.get(dpid, {})
		bandwidth['Used'] = simple_switch.rate_used.get(dpid, {})
		body = json.dumps(bandwidth, indent=4, sort_keys=True)
		return Response(content_type='application/json', body=body)



