# Copyright (c) 2012 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""The hypervisors admin extension."""

import webob.exc

from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import compute
from nova import exception
from nova.i18n import _
from nova import servicegroup

# begin:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>
from oslo_log import log as logging
from nova import objects
from nova.compute import arch
from nova.api.openstack import common
from nova.i18n import _LI
from nova.virt.libvirt import config as vconfig
from oslo_serialization import jsonutils
from lxml import etree

LOG = logging.getLogger(__name__)
# end:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>

ALIAS = "os-hypervisors"
authorize = extensions.os_compute_authorizer(ALIAS)
# begin:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>
VIR_CPU_COMPARE_ERROR = -1
VIR_CPU_COMPARE_INCOMPATIBLE = 0
VIR_CPU_COMPARE_IDENTICAL = 1
VIR_CPU_COMPARE_SUPERSET = 2
# end:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>


class HypervisorsController(wsgi.Controller):
    """The Hypervisors API controller for the OpenStack API."""

    def __init__(self):
        self.host_api = compute.HostAPI()
        # begin:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>
        self.compute_api = compute.API()
        # end:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>
        self.servicegroup_api = servicegroup.API()
        super(HypervisorsController, self).__init__()

    def _view_hypervisor(self, hypervisor, service, detail, servers=None,
                         **kwargs):
        alive = self.servicegroup_api.service_is_up(service)
        hyp_dict = {
            'id': hypervisor.id,
            'hypervisor_hostname': hypervisor.hypervisor_hostname,
            'state': 'up' if alive else 'down',
            'status': ('disabled' if service.disabled
                       else 'enabled'),
            }

        if detail and not servers:
            for field in ('vcpus', 'memory_mb', 'local_gb', 'vcpus_used',
                          'memory_mb_used', 'local_gb_used',
                          'hypervisor_type', 'hypervisor_version',
                          'free_ram_mb', 'free_disk_gb', 'current_workload',
                          'running_vms', 'cpu_info', 'disk_available_least',
                          'host_ip'):
                hyp_dict[field] = hypervisor[field]

            hyp_dict['service'] = {
                'id': service.id,
                'host': hypervisor.host,
                'disabled_reason': service.disabled_reason,
                }

        if servers:
            hyp_dict['servers'] = [dict(name=serv['name'], uuid=serv['uuid'])
                                   for serv in servers]

        # Add any additional info
        if kwargs:
            hyp_dict.update(kwargs)

        return hyp_dict

    @extensions.expected_errors(())
    def index(self, req):
        context = req.environ['nova.context']
        authorize(context)
        compute_nodes = self.host_api.compute_node_get_all(context)
        req.cache_db_compute_nodes(compute_nodes)
        return dict(hypervisors=[self._view_hypervisor(
                                 hyp,
                                 self.host_api.service_get_by_compute_host(
                                     context, hyp.host),
                                 False)
                                 for hyp in compute_nodes])

    @extensions.expected_errors(())
    def detail(self, req):
        context = req.environ['nova.context']
        authorize(context)
        compute_nodes = self.host_api.compute_node_get_all(context)
        # begin:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>
        server_id = req.GET.get('server_id', None)
        if server_id:
            compute_nodes_after_filter = []
            instance = common.get_instance(self.compute_api, context,
                                           server_id)
            src_compute_info = objects.ComputeNode. \
                get_first_node_by_host_for_old_compat(context,
                                                      instance.host)
            if not instance.vcpu_model or not instance.vcpu_model.model:
                source_cpu_info = src_compute_info['cpu_info']
                info = jsonutils.loads(source_cpu_info)
                LOG.info(_LI('Instance launched has CPU info: %s'),
                         source_cpu_info)
                cpu = vconfig.LibvirtConfigCPU()
                cpu.arch = info['arch']
                cpu.model = info['model']
                cpu.vendor = info['vendor']
                cpu.sockets = info['topology']['sockets']
                cpu.cores = info['topology']['cores']
                cpu.threads = info['topology']['threads']
                for f in info['features']:
                    cpu.add_feature(vconfig.LibvirtConfigCPUFeature(f))
            else:
                cpu = self._vcpu_model_to_cpu_config(instance.vcpu_model)
            cpu_xml = cpu.to_xml()
            for compute_node in compute_nodes:
                dst_cpu_info = jsonutils.loads(compute_node['cpu_info'])
                ret = self._compareCPU(cpu_xml, dst_cpu_info)
                service = self.host_api.service_get_by_compute_host(
                    context, compute_node.host)
                state_is_up = self.servicegroup_api.service_is_up(service)
                status_is_disabled = service.disabled
                if compute_node['host'] == instance.host or not state_is_up or \
                        status_is_disabled:
                    continue
                if ret > 0 and src_compute_info['hypervisor_type'] == \
                        compute_node['hypervisor_type'] and \
                                src_compute_info['hypervisor_version'] <= \
                                compute_node['hypervisor_version']:
                    compute_nodes_after_filter.append(compute_node)
            compute_nodes = compute_nodes_after_filter
        # end:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>
        req.cache_db_compute_nodes(compute_nodes)
        return dict(hypervisors=[self._view_hypervisor(
                                 hyp,
                                 self.host_api.service_get_by_compute_host(
                                     context, hyp.host),
                                 True)
                                 for hyp in compute_nodes])

    # begin:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>
    def _compareCPU(self, xml, host_info):
        LOG.debug("Compare guest_cpu or src_host_cpu and dst_host_cpu")
        tree = etree.fromstring(xml)
        arch_node = tree.find('./arch')
        if arch_node is not None:
            if arch_node.text not in [arch.X86_64,
                                      arch.I686]:
                return VIR_CPU_COMPARE_INCOMPATIBLE

        model_node = tree.find('./model')
        if model_node is not None:
            if model_node.text != host_info.get('model'):
                return VIR_CPU_COMPARE_INCOMPATIBLE

        vendor_node = tree.find('./vendor')
        if vendor_node is not None:
            if vendor_node.text != host_info.get('vendor'):
                return VIR_CPU_COMPARE_INCOMPATIBLE

        # The rest of the stuff libvirt implements is rather complicated
        # and I don't think it adds much value to replicate it here.

        LOG.debug("Compare finished.")
        return VIR_CPU_COMPARE_IDENTICAL

    def _vcpu_model_to_cpu_config(self, vcpu_model):
        cpu_config = vconfig.LibvirtConfigGuestCPU()
        cpu_config.arch = vcpu_model.arch
        cpu_config.model = vcpu_model.model
        cpu_config.mode = vcpu_model.mode
        cpu_config.match = vcpu_model.match
        cpu_config.vendor = vcpu_model.vendor
        if vcpu_model.topology:
            cpu_config.sockets = vcpu_model.topology.sockets
            cpu_config.cores = vcpu_model.topology.cores
            cpu_config.threads = vcpu_model.topology.threads
        if vcpu_model.features:
            for f in vcpu_model.features:
                xf = vconfig.LibvirtConfigGuestCPUFeature()
                xf.name = f.name
                xf.policy = f.policy
                cpu_config.features.add(xf)
        return cpu_config
    # end:<wangzh21>:<Bugzilla - bug 75256>:<a>:<2016-11-17>

    @extensions.expected_errors(404)
    def show(self, req, id):
        context = req.environ['nova.context']
        authorize(context)
        try:
            hyp = self.host_api.compute_node_get(context, id)
            req.cache_db_compute_node(hyp)
        except (ValueError, exception.ComputeHostNotFound):
            msg = _("Hypervisor with ID '%s' could not be found.") % id
            raise webob.exc.HTTPNotFound(explanation=msg)
        service = self.host_api.service_get_by_compute_host(
            context, hyp.host)
        return dict(hypervisor=self._view_hypervisor(hyp, service, True))

    @extensions.expected_errors((404, 501))
    def uptime(self, req, id):
        context = req.environ['nova.context']
        authorize(context)
        try:
            hyp = self.host_api.compute_node_get(context, id)
            req.cache_db_compute_node(hyp)
        except (ValueError, exception.ComputeHostNotFound):
            msg = _("Hypervisor with ID '%s' could not be found.") % id
            raise webob.exc.HTTPNotFound(explanation=msg)

        # Get the uptime
        try:
            host = hyp.host
            uptime = self.host_api.get_host_uptime(context, host)
        except NotImplementedError:
            common.raise_feature_not_supported()

        service = self.host_api.service_get_by_compute_host(context, host)
        return dict(hypervisor=self._view_hypervisor(hyp, service, False,
                                                     uptime=uptime))

    @extensions.expected_errors(404)
    def search(self, req, id):
        context = req.environ['nova.context']
        authorize(context)
        hypervisors = self.host_api.compute_node_search_by_hypervisor(
                context, id)
        if hypervisors:
            return dict(hypervisors=[self._view_hypervisor(
                                     hyp,
                                     self.host_api.service_get_by_compute_host(
                                         context, hyp.host),
                                     False)
                                     for hyp in hypervisors])
        else:
            msg = _("No hypervisor matching '%s' could be found.") % id
            raise webob.exc.HTTPNotFound(explanation=msg)

    @extensions.expected_errors(404)
    def servers(self, req, id):
        context = req.environ['nova.context']
        authorize(context)
        compute_nodes = self.host_api.compute_node_search_by_hypervisor(
                context, id)
        if not compute_nodes:
            msg = _("No hypervisor matching '%s' could be found.") % id
            raise webob.exc.HTTPNotFound(explanation=msg)
        hypervisors = []
        for compute_node in compute_nodes:
            instances = self.host_api.instance_get_all_by_host(context,
                    compute_node.host)
            service = self.host_api.service_get_by_compute_host(
                context, compute_node.host)
            hyp = self._view_hypervisor(compute_node, service, False,
                                        instances)
            hypervisors.append(hyp)
        return dict(hypervisors=hypervisors)

    @extensions.expected_errors(())
    def statistics(self, req):
        context = req.environ['nova.context']
        authorize(context)
        stats = self.host_api.compute_node_statistics(context)
        return dict(hypervisor_statistics=stats)


class Hypervisors(extensions.V21APIExtensionBase):
    """Admin-only hypervisor administration."""

    name = "Hypervisors"
    alias = ALIAS
    version = 1

    def get_resources(self):
        resources = [extensions.ResourceExtension(ALIAS,
                HypervisorsController(),
                collection_actions={'detail': 'GET',
                                    'statistics': 'GET'},
                member_actions={'uptime': 'GET',
                                'search': 'GET',
                                'servers': 'GET'})]

        return resources

    def get_controller_extensions(self):
        return []
