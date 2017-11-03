# Copyright (c) 2011-2012 OpenStack Foundation
# All Rights Reserved.
# Copyright 2015 EasyStack, Inc.
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

from oslo_config import cfg

from nova import db
from oslo_log import log as logging
from nova.scheduler import filters

LOG = logging.getLogger(__name__)

opt = cfg.StrOpt('cascade_availability_zone_separator',
                 default="/",
                 help='The separator used between the domains')

CONF = cfg.CONF
CONF.register_opt(opt)
CONF.import_opt('default_availability_zone', 'nova.availability_zones')


class CascadeAvailabilityZoneFilter(filters.BaseHostFilter):
    """Filters Hosts by cascade availability zone.

    Works with aggregate metadata availability zones, using the key
    'availability_zone'
    Note: in theory a compute node can be part of multiple availability_zones
    """

    # Availability zones do not change within a request
    run_filter_once_per_request = True

    def host_passes(self, host_state, filter_properties):
        spec = filter_properties.get('request_spec', {})
        props = spec.get('instance_properties', {})
        availability_zone = props.get('availability_zone')

        # Must provide an availability zone
        if not availability_zone:
            return False

        context = filter_properties['context'].elevated()
        metadata = db.aggregate_metadata_get_by_host(
            context, host_state.host, key='availability_zone')
        if 'availability_zone' in metadata:
            return self.match(availability_zone, metadata['availability_zone'])
        else:
            return availability_zone == CONF.default_availability_zone

    def match(self, zone, metadata_zone):
        LOG.info('CascadeAvailabilityZoneFilter: zone = %s, metadata_zone =%s'
                 % (zone, metadata_zone))
        # zone format like {domain}/{tenant}/{zone}
        zone_separator = CONF.cascade_availability_zone_separator
        zone_array = zone.split(zone_separator)
        # metadata_zone is set, we just get first one.
        metadata_zone_array = list(metadata_zone)[0].split(zone_separator)

        if len(zone_array) > len(metadata_zone_array):
            return False
        for idx, z in enumerate(zone_array):
            if z != metadata_zone_array[idx]:
                return False

        return True
