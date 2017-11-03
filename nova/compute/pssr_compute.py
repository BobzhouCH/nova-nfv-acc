#!/usr/bin/env python
from nova import utils
from oslo_log import log as logging
import pdb
import re
from oslo_context.context import get_admin_context
import socket

# from nova import db
# from nova.conductor import rpcapi as conductor_rpcapi

LOG = logging.getLogger(__name__)
support_nic_type = ['82599', 'AABBCCDDXX']


class port_info(object):
    """get compute node's net info"""

    def __init__(self):
        super(port_info, self).__init__()
        self.port_of_prv_network = []
        self.lspci_rsp = utils.execute('lspci')[0]
        self.ifconfig = utils.execute('ifconfig', '-a')[0].split('\n\n')
        self.ethinfo = []
        self.get_ethinfo()
        self.set_port_filter()

    def set_port_filter(self):
        for port in self.ethinfo:
            i = self.ethinfo.index(port)
            if any([nic_type in port['device'] for nic_type in support_nic_type]):
                self.ethinfo[i]['pci_passthrough_supported'] = 'yes'
                self.ethinfo[i]['pci_sriov_supported'] = 'yes'
            else:
                self.ethinfo[i]['pci_passthrough_supported'] = 'no'
                self.ethinfo[i]['pci_sriov_supported'] = 'no'

    def get_eth_pci(self, ethname):
        eth_pci_pattern = 'bus-info: (\S+)'
        ethtool_rsp = utils.execute("ethtool", "-i", ethname)[0]
        pci = re.search(eth_pci_pattern, ethtool_rsp)
        return pci.group(1)

    def get_eth_auto(self, ethname):
        eth_auto_pattern = 'Advertised auto-negotiation: (\S+)'
        ethtool_rsp = utils.execute("ethtool", ethname)[0]
        auto = re.search(eth_auto_pattern, ethtool_rsp)
        if auto:
            return auto.group(1)
        else:
            return '0'

    def get_eth_numa(self, ethname):
        try:
            f = open("/sys/class/net/" + ethname + "/device/numa_node")
            numa = f.readlines()
            f.close()
            return numa[0].split("\n")[0]
        except IOError:
            return None

    def get_eth_max_vfnum(self, ethname):
        try:
            f = open("/sys/class/net/" + ethname + "/device/sriov_totalvfs")
            max_vfnum = f.readlines()
            f.close()
            return max_vfnum[0].split("\n")[0]
        except IOError:
            return 0

    def get_eth_device(self, pci):
        eth_device_pattern = pci[5:] + ' (.*)'
        device = re.search(eth_device_pattern, self.lspci_rsp)
        if device:
            return device.group(1)
        return None

    def get_ethinfo(self):
        eth_name_pattern = '^eth[0-9]{1,3}'
        eth_mac_pattern = 'ether (\S+)'
        for str in self.ifconfig:
            eth = re.search(eth_name_pattern, str)
            if eth:
                eth = eth.group()
                mac = re.search(eth_mac_pattern, str)
                pci = self.get_eth_pci(eth)
                numa = self.get_eth_numa(eth)
                if numa:
                    numa = int(numa)
                max_vfnum = int(self.get_eth_max_vfnum(eth))
                auto = self.get_eth_auto(eth)
                device = self.get_eth_device(pci)
                self.ethinfo.append({"auto": auto, "processor": numa, "name": eth, "mac": mac.group(1), "pci": pci,
                                     "pci_passthrough_supported": 'yes', "pci_sriov_supported": 'yes', "device": device,
                                     "max_vfnum": max_vfnum})


class intf_info(port_info):
    def __init__(self):
        super(intf_info, self).__init__()
        self.intfinfo = []
        for ethinfo in self.ethinfo:
            self.intfinfo.append(
                {"name": ethinfo["name"], "provider_networks": "", 'network_type': "", "type": "ethernet", "vlan_id": 0,
                 "ports": ethinfo["name"], "support_config": 'yes', "uses": "", "used_by": "",
                 "attributes": "MTU=1500"})
        self.ovs_vsctl_rsp = utils.execute("ovs-vsctl", "show", **{'run_as_root': 'True'})[0]
        self.get_intfinfo()
        self.set_support_config()
        self.ethinfo.sort(key=lambda e: e.__getitem__('name'))
        self.intfinfo.sort(key=lambda e: e.__getitem__('name'))
        LOG.info(self.ethinfo)
        LOG.info(self.intfinfo)

    def get_port_by_name(self, name):
        for port in self.ethinfo:
            if port['name'] == name:
                return port
        return 0

    def set_support_config(self):
        for intf in self.intfinfo:
            i = self.intfinfo.index(intf)
            if intf['network_type'] != '':  # the interface have been used by system,so user can't config it.
                self.intfinfo[i]["support_config"] = 'no'
            else:
                port = self.get_port_by_name(intf['name'])
                if port['pci_passthrough_supported'] == 'no' and port['pci_sriov_supported'] == 'no':
                    self.intfinfo[i]["support_config"] = 'no'  # default is 'yes'

    def set_eth_physnet(self, eth, network_type):
        for intfinfo in self.intfinfo:
            if intfinfo["name"] == eth:
                i = self.intfinfo.index(intfinfo)
                if "" == self.intfinfo[i]["network_type"]:
                    self.intfinfo[i]["network_type"] = network_type
                else:
                    self.intfinfo[i]["network_type"] = self.intfinfo[i]["network_type"] + "," + network_type

                LOG.info("set_eth_physnet,eth=%s,network_type=%s", eth, self.intfinfo[i]["network_type"])
                return 0
        LOG.error("set_eth_physnet,eth=%s,network_type=%s", eth, network_type)
        return -1

    def need_eth_dpdk_info(self, eth):
        for intfinfo in self.intfinfo:
            if intfinfo["name"] == eth:  # have been get dpdk_eth info
                return False
        return True

    def get_dpdk_eth_mac_by_udev(self, eth):
        # /etc/udev/rules.d/70-persistent-net.rules
        try:
            f = open("/etc/udev/rules.d/70-persistent-net.rules")
            lines = f.readlines()
            f.close()
            eth_mac_pattern = 'ATTR{address}=="(\S+)"'
            for line in lines:
                if eth in line:
                    mac = re.search(eth_mac_pattern, line)
                    LOG.info("get_dpdk_eth_mac, mac = %s" % mac.group(1))
                    return mac.group(1)
            LOG.error("get_dpdk_eth_mac,can't get mac addr from 70-persistent-net.rules")
            return None
        except IOError:
            return None

    def get_prv_dpdk_eth_pci(self):
        # if config pass-through port,there will be more than one dpdk dev being seen by cmd:dpdk-devbind --status;
        # we can't deal with that situation;
        # also we should not get pci addr from db(because we prepare the DATA is for db update in the end)

        # dpdk-devbind --status
        # list of supported DPDK drivers
        dpdk_drivers = ["drv=igb_uio", "drv=vfio-pci", "drv=uio_pci_generic"]
        rsps = utils.execute('dpdk-devbind', '--status')[0].split('\n')
        i = 0
        dpdk_eth_lines = []
        for line in rsps:
            if any([driver in line for driver in dpdk_drivers]):
                i = i + 1
                dpdk_eth_lines.append(line)
        if 1 == i:  # only one dpdk eth is valid,can't process more than one dpdk eth
            pci_pattern = "^(\S+)"
            pci = re.search(pci_pattern, dpdk_eth_lines[0]).group()
            LOG.info("get_prv_dpdk_eth_pci,pci = %s" % pci)
            return pci
        LOG.error("get_prv_dpdk_eth_pci,More than one dpdk device,can't get pci addr")
        return None

    def get_dpdk_eth_numa(self, pci):
        # /sys/bus/pci/devices/0000\:83\:00.0/numa_node        
        try:
            f = open("/sys/bus/pci/devices/%s/numa_node" % pci)
            numa = f.readlines()
            f.close()
            return numa[0].split("\n")[0]
        except IOError:
            return None

    def add_prv_dpdk_port(self, eth, pci):
        mac = self.get_dpdk_eth_mac_by_udev(eth)
        numa = self.get_dpdk_eth_numa(pci)
        if numa:
            numa = int(numa)
        device = self.get_eth_device(pci)
        self.ethinfo.append(
            {"auto": "Yes", "processor": numa, "name": eth, "mac": mac, "pci": pci,
             "pci_passthrough_supported": 'no', "pci_sriov_supported": 'no',
             "device": device,
             "max_vfnum": 0})
        self.intfinfo.append(
            {"name": eth, "provider_networks": "", "network_type": "", "type": "ethernet",
             "vlan_id": 0, "ports": eth, "support_config": 'no', "uses": "", "used_by": "",
             "attributes": "MTU=1500"})

    def get_br_prv_eth_pci(self):
        cmd = "ovs-vsctl get Open_vSwitch . other_config"
        ovs_config_pcis= utils.execute("sh", "-c",cmd , **{'run_as_root': 'True'})[0].split("-w")
        pattern = "(\S\S\S\S:\S\S:\S\S.\S)"
        pcis=[]
        for line in ovs_config_pcis:
            pci = re.search(pattern, line)
            if pci:
                pcis.append(pci.group())
        if pcis:
            LOG.info("get_br_prv_eth_pci, pcis = %s", pcis)
            return pcis
        LOG.error("get_br_prv_eth_pci, fail")
        return -1

    def get_eth_by_pci(self,pci):
        cmd = "cat /var/log/dmesg | grep " + "'" + pci + " eth'"
        rsp = utils.execute("sh","-c",cmd,**{"run_as_root":"True"})[0]
        pattern = pci + " (eth[0-9]{1,3})"
        eth = re.search(pattern, rsp)
        if eth:
            eth = eth.group(1)
            LOG.info("get_eth_by_pci, eth = %s",eth)
            return eth
        LOG.error("get_eth_by_pci, fail")
        return -1

    def get_br_prv_eth(self):
        pcis = self.get_br_prv_eth_pci()
        for pci in pcis:
            eth = self.get_eth_by_pci(pci)
            self.port_of_prv_network.append(eth)
            if self.need_eth_dpdk_info(eth):
                self.add_prv_dpdk_port(eth,pci)
                self.set_eth_physnet(eth, "prv_network")
        if pcis:
            return 0
        LOG.error("get_br_prv_eth, fail")
        return -1

    def get_br_mgmt_eth_bond(self):
        pattern_bond = 'br-mgmt--br-(ovs-bond[0-9]{1,3})'
        #from  br-mgmt--br-ovs-bond0 ,get  ovs-bond0
        ovs_bond_port = re.search(pattern_bond, self.ovs_vsctl_rsp)
        if ovs_bond_port == None:
            return -1
        #split Port ,find out :
        #        Port "ovs-bond0"
        #            Interface "eth4"
        #            Interface "eth9"
        ovs_vsctl_rsp_s = self.ovs_vsctl_rsp.split("Port")
        pattern ="\""+ ovs_bond_port.group(1) +"\""
        for line in ovs_vsctl_rsp_s:
            eths = re.search(pattern,line)
            if eths:
                eths = line.split("Interface")
                pattern = "\"(eth[0-9]{1,3})\""
                for line in eths:
                    eth = re.search(pattern, line)
                    if eth:
                        eth = eth.group(1)
                        self.set_eth_physnet(eth, "mgmt_network")
                return 0
        LOG.error("get_br_mgmt_eth fail")
        return -1

    def get_br_mgmt_eth(self):
        pattern = 'br-mgmt--br-(eth[0-9]{1,3})'
        eth = re.search(pattern, self.ovs_vsctl_rsp)
        if eth:
            eth = eth.group(1)
            return self.set_eth_physnet(eth, "mgmt_network")
        return self.get_br_mgmt_eth_bond()

    def get_br_roller_eth(self):
        pattern = 'br-roller--br-(eth[0-9]{1,3})'
        eth = re.search(pattern, self.ovs_vsctl_rsp)
        if eth:
            eth = eth.group(1)
            return self.set_eth_physnet(eth, "boot_network")
        LOG.error("get_br_roller_eth fail")
        return -1

    def get_br_storage_eth_bond(self):
        pattern_bond = 'br-storage--br-(ovs-bond[0-9]{1,3})'
        #from  br-storage--br-ovs-bond0 ,get  ovs-bond0
        ovs_bond_port = re.search(pattern_bond, self.ovs_vsctl_rsp)
        if ovs_bond_port == None:
            return -1
        #split Port ,find out :
        #        Port "ovs-bond0"
        #            Interface "eth4"
        #            Interface "eth9"
        ovs_vsctl_rsp_s = self.ovs_vsctl_rsp.split("Port")
        pattern ="\""+ ovs_bond_port.group(1) +"\""
        for line in ovs_vsctl_rsp_s:
            eths = re.search(pattern,line)
            if eths:
                eths = line.split("Interface")
                pattern = "\"(eth[0-9]{1,3})\""
                for line in eths:
                    eth = re.search(pattern, line)
                    if eth:
                        eth = eth.group(1)
                        self.set_eth_physnet(eth, "storage_network")
                return 0
        LOG.error("get_br_storage_eth fail")
        return -1

    def get_br_storage_eth(self):
        pattern = 'br-storage--br-(eth[0-9]{1,3})'
        eth = re.search(pattern, self.ovs_vsctl_rsp)
        if eth:
            eth = eth.group(1)
            return self.set_eth_physnet(eth, "storage_network")
        return self.get_br_storage_eth_bond()

    def get_br_ex_eth_bond(self):
        pattern_bond = 'br-ex--br-(ovs-bond[0-9]{1,3})'
        #from  br-ex--br-ovs-bond0 ,get  ovs-bond0
        ovs_bond_port = re.search(pattern_bond, self.ovs_vsctl_rsp)
        if ovs_bond_port == None:
            return -1
        #split Port ,find out :
        #        Port "ovs-bond0"
        #            Interface "eth4"
        #            Interface "eth9"
        ovs_vsctl_rsp_s = self.ovs_vsctl_rsp.split("Port")
        pattern ="\""+ ovs_bond_port.group(1) +"\""
        for line in ovs_vsctl_rsp_s:
            eths = re.search(pattern,line)
            if eths:
                eths = line.split("Interface")
                pattern = "\"(eth[0-9]{1,3})\""
                for line in eths:
                    eth = re.search(pattern, line)
                    if eth:
                        eth = eth.group(1)
                        self.set_eth_physnet(eth, "extern_network")
                return 0
        LOG.error("get_br_ex_eth fail")
        return -1

    def get_br_ex_eth(self):
        pattern = 'br-ex--br-(eth[0-9]{1,3})'
        eth = re.search(pattern, self.ovs_vsctl_rsp)
        if eth:
            eth = eth.group(1)
            return self.set_eth_physnet(eth, "extern_network")
        if self.get_br_ex_eth_bond():
            LOG.info("get_br_ex_eth fail,extern networks may not in compute node")
        return 0  # extern networks may not in compute node

    def get_intfinfo(self):
        if self.get_br_prv_eth():     return -1
        if self.get_br_mgmt_eth():    return -1
        if self.get_br_roller_eth():  return -1
        if self.get_br_storage_eth(): return -1
        if self.get_br_ex_eth():      return -1
        return 0


class pssr_db(intf_info):
    def __init__(self):
        self.physerver = socket.gethostname()
        self.context = get_admin_context()
        self.node_id = self.get_node_id_from_name(self.context, self.physerver)
        if self.node_id == -1:
            return -1
        super(pssr_db, self).__init__()
        self.db_create_or_update_ports_table(self.context, self.node_id, self.ethinfo)
        self.db_create_or_update_interfaces_table(self.context, self.node_id, self.intfinfo)

    def get_node_id_from_name(self, context, physerver):
        node_ref = self.db.compute_node_get_all_by_host(context, physerver)
        if node_ref:
            return node_ref[0]["id"]
        LOG.error("get_node_id_from_name fail, physerver= %s" % physerver)
        return -1

    def find_item_in_pool(self, item, pool):
        for p in pool:
            if item["name"] == p["name"]:
                return p
        return False

    def is_item_need_update(self, item, item_db):
        for key, value in item.items():
            if item_db[key] != value:
                LOG.info("is_item_need_update key = %s, value: %s VS %s " % (key,item_db[key],value))
                return True
        return False

    def is_port_plug_out(self,pci):
        if self.get_eth_device(pci):
            return False
        return True

    def db_create_or_update_ports_table(self, context, node_id, ports_info):
        ports_from_db = self.db.nfv_port_get_by_node_id(context, node_id)
        LOG.info("db_create_or_update_ports_table,ports_from_db = %s" % ports_from_db)
        for port in ports_info:
            port["node_id"] = node_id
            port["nic_id"] = port["name"]  # for db search
            item_db = self.find_item_in_pool(port, ports_from_db)
            if item_db:
                # update db
                if self.is_item_need_update(port, item_db):
                    self.db.nfv_port_resource_update(context, node_id, port['nic_id'], port)
                    LOG.warn("db_create_or_update_ports_table,physical nic have been changed.")
                    LOG.warn("OLD nic info = %s;NEW nic info = %s" %(item_db,port))
                continue
            # create db
            self.db.nfv_port_resource_create(context, port)

        #delete plug out port item
        #need get new db data
        ports_from_db = self.db.nfv_port_get_by_node_id(context, node_id)
        for port_db in ports_from_db:
            port = self.find_item_in_pool(port_db, ports_info)
            if not port:
                if self.is_port_plug_out(port_db['pci']):  #physical nic have been pluged out
                    self.db.nfv_port_delete(self.context, self.node_id, port_db['nic_id'])
                    self.db.nfv_interface_delete(self.context, self.node_id, port_db['nic_id'])
                    LOG.warn("db_create_or_update_ports_table,physical nic have been pluged out.")
                    LOG.warn("DO nfv_port_delete and nfv_interface_delete ,nic info = %s" % port_db)
                elif port_db['name'] in self.port_of_prv_network:
                    LOG.info("db_create_or_update_ports_table,port_of_prv_network have been in db table,don't need update")
                else:
                    LOG.info("db_create_or_update_ports_table,maybe is a pass-through port;it have been in db table,don't need update")

    def db_create_or_update_interfaces_table(self, context, node_id, interfaces_info):
        interfaces_from_db = self.db.nfv_interface_get_by_node_id(context, node_id)
        LOG.info("db_create_or_update_interfaces_table,interfaces_from_db = %s" % interfaces_from_db)
        for interface in interfaces_info:
            item_db = self.find_item_in_pool(interface, interfaces_from_db)
            if item_db:
                # update support_config field
                item_db['support_config'] = interface['support_config']
                self.db.nfv_interface_resource_update(context, node_id, item_db['nic_id'], item_db)
                continue
            # create interface db
            interface["node_id"] = node_id
            interface["nic_id"] = interface["name"]  # for db search
            self.db.nfv_interface_resource_create(context, interface)


class pssr(pssr_db):
    def __init__(self, conductor_api):
        self.db = conductor_api
        super(pssr, self).__init__()
        import os
        self.pid = os.getpid()
        output, status = utils.execute("chmod", "+x", "/etc/rc.d/rc.local",
                                       **{'run_as_root': 'True'})
        output, status = utils.execute("chmod", "+x", "/etc/rc.local",
                                       **{'run_as_root': 'True'})

    def set_whitelist_ps(self, pci, physnet):
        LOG.info("set_whitelist_ps,pci=%s,physnet=%s", pci, physnet)
        paras = "/^scheduler_driver/a\pci_passthrough_whitelist={\"address\":\"" + pci + "\",\"physical_network\":\"" + physnet + "\"}"
        output, status = utils.execute("sed", "-i", paras, "/etc/nova/nova.conf", **{'run_as_root': 'True'})
        if status == "": return 0
        LOG.error("set_whitelist_ps,status= %s,output= %s", status, output)
        return status

    def unset_whitelist_ps(self, pci, physnet):
        LOG.info("unset_whitelist_ps,pci=%s,physnet=%s", pci, physnet)
        paras = "/^pci_passthrough_whitelist={\"address\":\"" + pci + "\",\"physical_network\":\"" + physnet + "\"}/d"
        output, status = utils.execute("sed", "-i", paras, "/etc/nova/nova.conf", **{'run_as_root': 'True'})
        if status == "": return 0
        LOG.error("unset_whitelist_ps,status= %s,output= %s", status, output)
        return status

    def set_whitelist_sriov(self, eth, physnet):
        LOG.info("set_whitelist_sriov,eth=%s,physnet=%s", eth, physnet)
        paras = "/^scheduler_driver/a\pci_passthrough_whitelist={\"devname\":\"" + eth + "\",\"physical_network\":\"" + physnet + "\"}"
        output, status = utils.execute("sed", "-i", paras, "/etc/nova/nova.conf", **{'run_as_root': 'True'})
        if status == "": return 0
        LOG.error("set_whitelist_sriov,status= %s,output= %s", status, output)
        return status

    def unset_whitelist_sriov(self, eth, physnet):
        LOG.info("unset_whitelist_sriov,eth=%s,physnet=%s", eth, physnet)
        paras = "/^pci_passthrough_whitelist={\"devname\":\"" + eth + "\",\"physical_network\":\"" + physnet + "\"}/d"
        output, status = utils.execute("sed", "-i", paras, "/etc/nova/nova.conf", **{'run_as_root': 'True'})
        if status == "": return 0
        LOG.error("unset_whitelist_sriov,status= %s,output= %s", status, output)
        return status

    def physical_device_mapping(self, eth, physnet):
        LOG.info("physical_device_mapping, eth = %s,physnet = %s", eth, physnet)
        #first time mapping ?

        try:
            paras0 = "a=$(sed -n   '$p'  '/etc/neutron/plugins/ml2/sriov_agent.ini') ; echo $a"
            line, status =utils.execute("sh", "-c", paras0, **{'run_as_root': 'True'})
            mapping_pattern = 'physical_device_mappings=(\S+)'
            mapping_pairs = None

            if "physical_device_mappings=" in line:
                mapping_pairs = re.search(mapping_pattern, line)

        except IOError:
            LOG.error("physical_device_mapping, eth = %s,physnet = %s", eth, physnet)
            return None
        #no,not first time mapping;add configure pair to the end.
        if mapping_pairs:
            paras = "s/^physical_device_mappings=.*/&,%s:%s/" % (physnet, eth)

         #yes,first time mapping;add a new line
        if mapping_pairs == None:
            paras = "/^\[sriov_nic\]/a\physical_device_mappings=%s:%s" % (physnet, eth)

        LOG.info("physical_device_mapping paras= %s", paras)
        output, status = utils.execute("sed", "-i", paras, "/etc/neutron/plugins/ml2/sriov_agent.ini",
                                       **{'run_as_root': 'True'})
        if status == "": return 0
        LOG.error("physical_device_mapping,status= %s,output= %s", status, output)
        return status

    def physical_device_unmap(self, eth, physnet):
        LOG.info("physical_device_unmap, eth = %s,physnet = %s", eth, physnet)
        #if the last unmap?
        try:
            paras0 = "a=$(sed -n   '$p'  '/etc/neutron/plugins/ml2/sriov_agent.ini') ; echo $a"
            line, status =utils.execute("sh", "-c", paras0, **{'run_as_root': 'True'})
            mapping_pattern = 'physical_device_mappings=(\S+)'
            is_last_pair = None
            if "physical_device_mappings=" in line:
                mapping_pairs = re.search(mapping_pattern, line)
                is_last_pair = re.search(",", mapping_pairs.group(1))
        except IOError:
            LOG.error("physical_device_unmap, eth = %s,physnet = %s", eth, physnet)
            return None
        #no,NOT the last unmap;
        if is_last_pair:
            pair_not_at_head_pattern = ",%s:%s" % (physnet, eth)
            delete_head_pair     = "%s:%s," % (physnet, eth)
            delete_not_head_pair = ",%s:%s" % (physnet, eth)
            is_pair_not_at_head = re.search(pair_not_at_head_pattern, mapping_pairs.group(1))
            if is_pair_not_at_head:
                paras = "s/" + delete_not_head_pair + "//g"
            else:
                paras = "s/" + delete_head_pair + "//g"

        #yes ,It's the last unmap;need delete all line.
        if is_last_pair == None:
            paras = "/^physical_device_mappings=" + physnet + ":" + eth + "/d"

        LOG.info("physical_device_unmap paras= %s",paras)
        output, status = utils.execute("sed", "-i", paras, "/etc/neutron/plugins/ml2/sriov_agent.ini",
                                       **{'run_as_root': 'True'})
        if status == "": return 0
        LOG.error("physical_device_unmap,status= %s,output= %s", status, output)
        return status

    def reboot_nova_compute(self):
        LOG.info("reboot_nova_compute,now")
        utils.execute("systemctl", "restart", "openstack-nova-compute", **{'run_as_root': 'True'})

    def reboot_sriov_agent(self):
        LOG.info("reboot_sriov_agent,now")
        output, status = utils.execute("systemctl", "restart", "neutron-sriov-nic-agent", **{'run_as_root': 'True'})
        if status == "": return 0
        LOG.error("reboot_sriov_agent,status= %s,output= %s", status, output)
        return status

    def stop_sriov_agent(self):
        LOG.info("stop_sriov_agent,now")
        output, status = utils.execute("systemctl", "stop", "neutron-sriov-nic-agent", **{'run_as_root': 'True'})
        if status == "": return 0
        LOG.error("stop_sriov_agent,status= %s,output= %s", status, output)
        return status

    def ps_conf(self, eth, provider_networks):
        self.set_eth_up(eth)
        LOG.info("ps_conf,eth=%s,provider_networks=%s", eth, provider_networks)
        pci = self.get_pci(eth)
        if pci == -1:
            LOG.error("ps_conf,get pci fail")
            return -1
        status = self.set_whitelist_ps(pci, provider_networks)
        if status == 0:
            self.reboot_nova_compute()  # reboot suceed or not,need check in nova api moudule.
        LOG.error("ps_conf,set whitelist fail ,status=%s", status)
        return status


    def setvf(self, eth, vfnum):
        LOG.info("setvf,eth = %s ,vfnum = %s", eth, vfnum)
        paras0 = "echo %s > /sys/class/net/%s/device/sriov_numvfs" % ("0", eth)
        paras = "echo %s > /sys/class/net/%s/device/sriov_numvfs" % (vfnum, eth)
        output, status = utils.execute("sh", "-c", paras0, **{'run_as_root': 'True'})
        if status != "":
            LOG.error("setvf to 0 fail,status = %s,output = %s", status, output)
            return status
        output, status = utils.execute("sh", "-c", paras, **{'run_as_root': 'True'})
        if status != "":
            LOG.error("setvf fail,status = %s,output = %s", status, output)
            return status

        # deal with compute node reboot
        if int(vfnum) > 0:
            # like:echo "echo '7' > /sys/class/net/eth3/device/sriov_numvfs" >> /etc/rc.local
            paras_s = 'echo "' + paras + '" >> /etc/rc.d/rc.local'
            output, status = utils.execute("sh", "-c", paras_s, **{'run_as_root': 'True'})
        elif int(vfnum) == 0:
            paras = "/\/sys\/class\/net\/%s\/device\/sriov_numvfs/d" % eth
            output, status = utils.execute("sed", "-i", paras, "/etc/rc.d/rc.local",
                                           **{'run_as_root': 'True'})
        return 0


    def set_eth_up(self, eth):
        output, status = utils.execute('sh', '-c', "ifconfig " +  eth +  " up", **{'run_as_root': 'True'})
        LOG.info("set_eth_up: ifconfig %s up" % eth)


    def sr_conf(self, eth, vfnum, provider_networks):
        self.set_eth_up(eth)
        LOG.info("sr_conf, vfnum = %s,eth = %s, provider_networks = %s", vfnum, eth, provider_networks)
        status = self.stop_sriov_agent()
        if status != 0:  return status
        status = self.setvf(eth, vfnum)
        if status != 0:  return status
        status = self.set_whitelist_sriov(eth, provider_networks)
        if status != 0:  return status
        status = self.physical_device_mapping(eth, provider_networks)
        if status != 0:  return status
        status = self.reboot_sriov_agent()
        if status != 0:  return status
        self.reboot_nova_compute()


    def get_pci(self, eth):
        for ethinfo in self.ethinfo:
            if ethinfo["name"] == eth:
                if ethinfo["pci"] == "":
                    LOG.error("get_pci,pci value is NULL")
                    return -1
                return ethinfo["pci"][4:]
        LOG.error("get_pci,no pci found.fail")
        return -1


    def ps_unset(self, eth, physnet):
        LOG.info("ps_unset,eth = %s,physnet = %s", eth, physnet)
        pci = self.get_pci(eth)
        if pci == -1:
            LOG.error("ps_unset,get pci fail")
            return -1
        status = self.unset_whitelist_ps(pci, physnet)
        if status != 0:  return status
        self.reboot_nova_compute()


    def sr_unset(self, eth, physnet):
        LOG.info("sr_unset,eth = %s,physnet = %s", eth, physnet)
        status = self.stop_sriov_agent()
        if status != 0:  return status
        status = self.unset_whitelist_sriov(eth, physnet)
        if status != 0:  return status
        status = self.physical_device_unmap(eth, physnet)
        if status != 0:  return status
        status = self.setvf(eth, "0")
        if status != 0:  return status
        status = self.reboot_sriov_agent()
        if status != 0:  return status
        self.reboot_nova_compute()


    def pssr_unset(self, last_nt, eth, physnet):
        self.set_eth_up(eth)
        if last_nt == "pci-passthrough":
            return self.ps_unset(eth, physnet)
        elif last_nt == "pci-sriov":
            return self.sr_unset(eth, physnet)
        else:
            LOG.error("pssr_unset,unknown last_nt,fail")
            return -1


    def pssr_conf(self, req):
        LOG.info("pssr_conf,req = %s" % req)
        nt = req['network_type']
        last_nt = req['last_network_type']
        eth = req['ports'][0]
        vfnum = req['vfnum']
        provider_networks = req['provider_networks'][0]
        if nt == 'pci-passthrough':
            return self.ps_conf(eth, provider_networks)
        elif nt == 'pci-sriov':
            return self.sr_conf(eth, vfnum, provider_networks)
        elif nt == 'none':
            return self.pssr_unset(last_nt, eth, provider_networks)
        else:
            LOG.error("pssr_conf,network_type para error!")
            return -1

# ps=pssr()
# print ps.intfinfo
