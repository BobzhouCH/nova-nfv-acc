
import os
import json
from nova import utils


from oslo_log import log as logging
LOG = logging.getLogger(__name__)

class NetronomeResourceManage:
    def __init__(self, file=None, bridge_name=None):
        if bridge_name:
            self.bridge_name = bridge_name
        else:
            self.bridge_name = 'br-acc'

        if file != None:
            self.tag_config_path = file
        else:
            self.tag_config_path = '/etc/nova/netronome_ports.json'

        self._resource_init()
    
    def _resource_init(self):
        #scan port resource usage and update json file
        cmd = 'ovs-vsctl list-ports %s' % (self.bridge_name)
        self.bridge_port_list = utils.execute("sh", "-c",cmd , **{'run_as_root': 'True'})[0].split("\n")[:-1]
        port_list = self._read_config()
        for port in port_list:
            if self._ovs_port_check(port['port_name']):
                port['is_used'] = True

            else:
                port['is_used'] = False
                port['bind_port'] = None
                port['bind_instance'] = None

        self._write_config(port_list)

    def _ovs_port_check(self, port_name):
        for port in self.bridge_port_list:
            if port_name == port.strip():
                return True

        return False

    def get_available_port(self):
        '''get a available port for using'''
        port_list = self._read_config()
        for port in port_list:
            if not port['is_used']:
                return port['port_id']

        return None

    def bind_port(self, port_id, bind_port_id, bind_instance_id):
        '''bind port with virtual port and instance id'''

        port_list = self._read_config()

        for port in port_list:
            if port['port_id'] == port_id:
                port['bind_port'] = str(bind_port_id)
                port['bind_instance'] = str(bind_instance_id)
                port['is_used'] = True
                LOG.debug('Success bind Netronome port %s' % port)
        self._write_config(port_list)


    def unbind_port(self, port_id):
        ''' unbind port and '''
        port_list = self._read_config()

        for port in port_list:
            if port['port_id'] == port_id:
                port['bind_port'] = None
                port['bind_instance'] = None
                port['is_used'] = False
                LOG.debug('Success unbind Netronome port %s' % port)
        self._write_config(port_list)

    def get_port_name(self, port_id):
        '''get port name by port id'''
        port_list = self._read_config()
        for port in port_list:
            if port['port_id'] == port_id:
                return port['port_name']

        return None


    def get_port_name_by_pci_slot(self, pci_slot):
        '''get port by pci slot'''
        port_list = self._read_config()
        for port in port_list:
            if port['pci_slot'] == str(pci_slot):
                return port['port_name']

        return None

    def get_port_name_by_bind_port(self, bind_port_id):
        '''get port name by binded port id'''
        port_list = self._read_config()
        for port in port_list:
            if port['bind_port'] == str(bind_port_id):
                return port['port_name']

        return None

    def get_port_id(self, port_name):
        '''get port id by port name'''
        port_list = self._read_config()
        for port in port_list:
            if port['port_name'] == port_name:
                return port['port_id']

        return None

    def get_port(self, port_id):
        '''get port info by port id'''
        port_list = self._read_config()
        for port in port_list:
            if port['port_id'] == port_id:
                return port

        return None


    def _write_config(self, config):
        '''write direction format config into tag_config_path tag config file'''

        if os.path.exists(self.tag_config_path):
            config_file = open(self.tag_config_path, 'w+')
        else:
            LOG.error('There is no %s' % (self.tag_config_path))
            return

        netronome = dict()
        netronome['netronome_ports'] = config
        json_format = json.dumps(netronome,sort_keys=True,
                                 indent=4, separators=(',', ':'))

        try:
            config_file.writelines(json_format)
        except Exception :
            LOG.error('Failed to write %s' % (self.tag_config_path))

    def _read_config(self):
        '''read tag_config_path tags config file 
        and return direction format variables'''

        if os.path.exists(self.tag_config_path):
            config_file = open(self.tag_config_path, 'r')
        else:
            output = 'There is no %s' % (self.tag_config_path)
            LOG.error('There is no %s' % (self.tag_config_path))
            return

        try:
            buf = config_file.read()
            netronome = json.loads(buf)
        except Exception:
            LOG.error('Failed to read %s' % (self.tag_config_path))

        return netronome['netronome_ports']

    def make_json(self, port_name_prefix, port_index_max ):
        '''generate neutron ports json'''

        port_list = []
        for i in range(0, port_index_max +1):
            port_name = port_name_prefix + str(i)
            port =dict()
            port["bind_instance"] = None
            port["bind_port"] = None
            port["is_used"] = False
            port["pci_slot"] = os.popen("ethtool -i %s | grep bus-info | cut -d ' ' -f 5" %port_name).read().strip()
            port["port_id"] = i
            port["port_name"] = port_name
            port["product_id"] = "6003"
            port["vender_id"] = "19ee"

            port_list.append(port)

        self._write_config(port_list)




if __name__ == '__main__':
    netro = NetronomeResourceManage()
    '''
    port_id = netro.get_available_port()
    print port_id

    port_name = netro.get_port_name(port_id)
    print port_name

    netro.bind_port(port_id, 1111, 2222)

    port = netro.get_port(port_id)
    print port

    netro.unbind_port(port_id)

    port = netro.get_port(port_id)
    print port
    '''
    #netro.make_json('sdn_v0.', 59)




