#!/usr/bin/env python
#
# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.lib import hub
hub.patch(thread=False)

# TODO:
#   Right now, we have our own patched copy of ovs python bindings
#   Once our modification is upstreamed and widely deployed,
#   use it
#
# NOTE: this modifies sys.path and thus affects the following imports.
# eg. oslo.config.cfg.

import logging
from ryu import log
log.early_init_log(logging.DEBUG)

from ryu.app import wsgi
from ryu.base.app_manager import AppManager


def main():
    log.init_log()
    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(['./ryu_controller.py'])

    contexts = app_mgr.create_contexts()
    services = []
    services.extend(app_mgr.instantiate_apps(**contexts))

    webapp = wsgi.start_service(app_mgr)
    if webapp:
        thr = hub.spawn(webapp)
        services.append(thr)

    print services
    try:
        hub.joinall(services)
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()