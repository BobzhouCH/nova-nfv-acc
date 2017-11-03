import webob
from webob import exc
from nova.api.openstack import wsgi
from nova.api.openstack import common
from nova.api.openstack import extensions
from nova import compute
from nova import exception
from nova import objects
from nova.i18n import _
from oslo_log import log as logging
LOG = logging.getLogger(__name__)
import oslo_messaging as messaging
from nova import rpc
from oslo_context.context import  get_admin_context
from oslo_config import cfg
from nova import db

ALIAS = 'PSSR'

class PssrController(wsgi.Controller):

      def show(self, req, id):
        '''
        :request url: /v2/{tenant_id}/pssr-url/{user_id}
        :param req: user_id:the user to caculate
        :param id: input the tenant_id which the user belong to
        :return:
        '''
        physerver  = req.GET.get("physerver")  #name don't include domain
        dev        = req.GET.get("dev")
        LOG.info("PssrController paras  id = %s, physerver=%s, dev=%s" % ( id, physerver, dev))
        context = req.environ['nova.context']
        node_id = self.get_node_id_from_name(context,physerver)
        if node_id == -1:
                return {"pssr_tag":{"results":[{"physerver_type":"not_compute"}]}}
        physerver_name = db.compute_node_get(context, node_id)["host"]   #name include domain
        cctxt = rpc.get_client(messaging.Target(topic="compute", server=physerver_name ))

        cctxt = cctxt.prepare(version='4.11')
        #        results = cctxt.cast(get_admin_context(), "ttt", a=1, b=2, c=3, d=4)
        if id == '1':
                return self.pssr_get_port_info(context,cctxt,node_id)
        elif id == '2':
                return self.pssr_get_intf_info(context,cctxt,node_id)
        elif id == "11":
                return self.pssr_get_port_conf(context,node_id,dev)
        elif id == "21":
                return self.pssr_get_intf_conf(context,node_id,dev)
        else:
                LOG.info("PssrController paras error, id = %s" % id)
                return {"pssr_tag":{"results":"error"}}

      def get_node_id_from_name(self,context,physerver):
        node_ref = db.compute_node_get_all(context)
        for node in node_ref:
                if physerver in node["host"]:
                        return node["id"]
        LOG.error("get_node_id_from_name fail, physerver= %s" % physerver)
        return -1

      def pssr_get_port_info(self,context,cctxt,node_id):
        func = "get_port_info"
        ports_info = {}
        #ports_info = cctxt.call(get_admin_context(), func , req="")
        #self.db_create_or_update_ports_table(context, node_id,ports_info)
        ports_info = db.nfv_port_get_by_node_id(context, node_id)
        LOG.info("PssrController %s, results = %s" % (func,ports_info))
        return {"pssr_tag":{"results":ports_info}}

      def pssr_get_intf_info(self,context,cctxt,node_id):
        func = "get_intf_info"
        interfaces_from_db = []
	ports_info = []
	results = []
        #interfaces_info = cctxt.call(get_admin_context(), func , req="")
        #self.db_create_or_update_interfaces_table(context,node_id,interfaces_info)
        interfaces_from_db = db.nfv_interface_get_by_node_id(context, node_id)
	ports_info = db.nfv_port_get_by_node_id(context, node_id)
	for intf in interfaces_from_db:
		for port in ports_info:
			if port["name"] == intf["name"]:
        	                intf["pci_passthrough_supported"] = port["pci_passthrough_supported"]
	                        intf["pci_sriov_supported"] = port["pci_sriov_supported"]				
				break
		results.append(intf)
				
        #interfaces_from_db.sort(key = lambda e:e.__getitem__('name'))
        LOG.info("PssrController %s, results = %s" % (func,results))
        return {"pssr_tag":{"results":results}}




      def pssr_get_port_conf(self,context,node_id,dev):
        port = []
	port = db.nfv_port_get_by_nic_id(context,node_id,dev)
        if port:	
		return {"pssr_tag":{"results":port}}
        LOG.error("pssr_get_port_conf fail ,port = %s" % dev)
        return {"pssr_tag":{"results":"pssr_get_port_conf fail"}}

      def pssr_get_intf_conf(self,context,node_id,dev):
	port = []
	intf = []	
        port = db.nfv_port_get_by_nic_id(context,node_id,dev)
        intf = db.nfv_interface_get_by_nic_id(context,node_id,dev)
	if port and intf:
        	intf["max_vfnum"] = port["max_vfnum"]
                return {"pssr_tag":{"results":intf}}
        LOG.error("pssr_get_intf_conf fail ,port = %s" % dev)
        return {"pssr_tag":{"results":"pssr_get_intf_conf fail"}}

      def create(self, req,body):
        '''
        :request url: /v2/{tenant_id}/pssr-url/{user_id}
        :param req: user_id:the user to caculate
        :param request: input user data
        :return:

        '''
        import time
        request = body["pssr_tag"]
        LOG.info("PssrController pssr_conf,req = %s" % req)
        LOG.info("PssrController pssr_conf,request = %s" % request)
        context = req.environ['nova.context']
        physerver = request["physerver"]
        node_id = self.get_node_id_from_name(context,physerver)
        physerver_name = db.compute_node_get(context, node_id)["host"]   #name include domain

        intf_conf =  self.pssr_get_intf_conf(context,node_id,request["name"])
        intf_conf = intf_conf["pssr_tag"]["results"]

        #repeat config or have been config other
        if intf_conf["network_type"] != "" and request["network_type"] != "none":
                return {"pssr_tag":{"results":"config fail,network have been config"}}
        if intf_conf["network_type"] == "" and request["network_type"] == "none":
                return {"pssr_tag":{"results":"config fail,repeat config"}}

        request["last_network_type"] = intf_conf["network_type"]
        cctxt = rpc.get_client(messaging.Target(topic="compute", server=physerver_name ))
        cctxt = cctxt.prepare(version='4.11')
        pid1 = cctxt.call(get_admin_context(), "get_nova_compute_pid" , req=request)
        cctxt.cast(get_admin_context(), "nfvi_pssr_conf" , req=request)
        for i in range(0,10):
                time.sleep(1)
                pid2 = cctxt.call(get_admin_context(), "get_nova_compute_pid" , req=request)
                #LOG.info("PssrController nfvi_pssr_conf,pid1 = %s,pid2 = %s" % (pid1,pid2))
                if pid1 == pid2:
                        continue
                else:
                        results = {"status":"success"}
                        self.pssr_update_intf_conf(context,node_id,intf_conf,request)
                        LOG.info("PssrController nfvi_pssr_conf,pid2 = %s,results = %s" % (pid2,results))
                        return {"pssr_tag":{"results":results}}

        LOG.error("nfvi_pssr_conf get_nova_compute_pid fail,pid2 = %s",pid2)
        return  {"pssr_tag":{"results":"config fail"}}

      def pssr_update_intf_conf(self,context,node_id,intf_conf,request):
        if request["network_type"] == "none":
                request["network_type"]=""
                request["provider_networks"]=""
                request["vfnum"]=0
        intf_conf["network_type"]=request["network_type"]
        intf_conf["vfnum"]=request["vfnum"]
        intf_conf["provider_networks"]=request["provider_networks"]
        db.nfv_interface_resource_update(context, node_id, intf_conf["nic_id"], intf_conf)
        LOG.info("pssr_update_intf_conf ,intf_conf= %s" % intf_conf)

class pssr(extensions.V21APIExtensionBase):
          """Server use statitistics support.
             currently only consider cpu ram sum by a user
             in a project.im
          """

          name = "pssr"
          alias = ALIAS
          version = 1

          def get_controller_extensions(self):
              controller = PssrController()
              extension = extensions.ControllerExtension(self, 'pssr-url', controller)
              return [extension]

          def get_resources(self):
               resources = []
               LOG.info("PSSR ================get_resources=============================")
               res = extensions.ResourceExtension('pssr-url',
                                           PssrController())
               resources.append(res)

               return resources
