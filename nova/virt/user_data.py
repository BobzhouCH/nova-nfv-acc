# Copyright 2016 EasyStack, Inc.
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

import base64
import email
from email.mime import multipart as mime_multipart
from email.mime import text as mime_text

from nova import utils


def _cloud_config(instance, admin_pass):
    """config default user with cloud-config:
    system_info:
      default_user:
        name: root
        plain_text_passwd: 'passw0rd'
        lock_passwd: false
        system: true

    set admin password(linux and windows) like this:
    #cloud-config
    password: admin_pass

    there we set username as 'root' and ignore default user

    refer to: https://easystack.atlassian.net/browse/EAS-283?focusedCommentId=12102
    """
    cfg = []
    cfg.append('#cloud-config')
    cfg.append('chpasswd:')
    cfg.append('  list: |')
    cfg.append('    root:%s' % admin_pass)
    cfg.append('  expire: false')
    return '\n'.join(cfg)


def _append_to_userdata(instance, cloud_cfg):
    user_data = instance.user_data

    cloud_cfg = mime_text.MIMEText(cloud_cfg)
    if user_data:
        ud = email.message_from_string(base64.b64decode(user_data))
        if ud.is_multipart():
            message = ud
        else:
            message = mime_multipart.MIMEMultipart()
            message.attach(ud)
        message.attach(cloud_cfg)
    else:
        message = cloud_cfg

    return base64.b64encode(message.as_string())


def update_metadata(context, instance, admin_pass):
    """add admin_pass to metadata(user_data / instance metadata)"""

    # cloud-config for cloud-init
    cloud_cfg = _cloud_config(instance, admin_pass)
    user_data = _append_to_userdata(instance, cloud_cfg)

    # meta for cloudbase-init. (maybe we could use cmd to set it?)
    meta = {'admin_pass': admin_pass}
    metadata = utils.instance_meta(instance)
    # metadata.update(meta)

    # update instance
    instance.user_data = user_data
    instance.metadata = metadata
    instance.save()
