# All Rights Reserved.
#    Copyright Lenovo, Inc
#    Authors:
#        Lei Li <lilei16@lenovo.com>
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


from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Boolean

from nova.i18n import _LI

from oslo_utils import timeutils
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    nfv_port_resource = Table('nfv_port_resource', meta,
        Column('id', Integer, primary_key=True, nullable=False),
        Column('created_at', DateTime, default=timeutils.utcnow),
        Column('updated_at', DateTime, onupdate=timeutils.utcnow),
        Column('deleted_at', DateTime),
        Column('node_id', Integer, nullable=True),
        Column('nic_id', String(length=255), nullable=True),
        Column('name', String(length=255), nullable=True),
        Column('mac', String(length=255), nullable=True),
        Column('pci', String(length=255), nullable=True),
	Column('pci_passthrough_supported', String(length=255), default='yes'),
	Column('pci_sriov_supported', String(length=255), default='yes'),
        Column('max_vfnum', Integer, nullable=True),
        Column('processor', Integer, nullable=True),
        Column('auto', String(length=255), nullable=True),
        Column('device', String(length=255), nullable=True),
        Column('deleted', String(length=36), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )
    shadow_nPar_resource = Table('shadow_nfv_port_resource', meta,
        Column('id', Integer, primary_key=True, nullable=False),
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('node_id', Integer, nullable=True),
        Column('nic_id', String(length=255), nullable=True),
        Column('name', String(length=255), nullable=True),
        Column('mac', String(length=255), nullable=True),
        Column('pci', String(length=255), nullable=True),
	Column('pci_passthrough_supported', String(length=255), default='yes'),
        Column('pci_sriov_supported', String(length=255), default='yes'),
        Column('max_vfnum', Integer, nullable=True),
        Column('processor', Integer, nullable=True),
        Column('auto', String(length=255), nullable=True),
        Column('device', String(length=255), nullable=True),
        Column('deleted', String(length=36), nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    try:
        table_names = ('nfv_port_resource', 'shadow_nfv_port_resource')
        for table_name in table_names:
            table = Table(table_name, meta, autoload=True)
            table.create()

    except Exception:
        LOG.info(repr(nfv_port_resource))
        LOG.exception(_LI('Exception while creating table.'))
        raise


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    table_name = ('nfv_port_resource')
    table = Table(table_name, meta, autoload=True)
    table.drop()
    table_name = ('shadow_nfv_port_resource')
    table = Table(table_name, meta, autoload=True)
    table.drop()



