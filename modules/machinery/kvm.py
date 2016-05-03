# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import logging
import libvirt

import xml.etree.ElementTree as ET

from lib.cuckoo.common.abstracts import LibVirtMachinery

from lib.cuckoo.common.abstracts import LibVirtMachinery
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError



class KVM(LibVirtMachinery):
    """Virtualization layer for KVM based on python-libvirt."""

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if configuration is invalid
        """
        if not self.options.kvm.dsn:
            raise CuckooMachineError("KVM DSN is missing, please add it to the config file")
        if not self.options.kvm.username:
            raise CuckooMachineError("KVM username is missing, please add it to the config file")
        if not self.options.kvm.password:
            raise CuckooMachineError("KVM password is missing, please add it to the config file")

        self.dsn = self.options.kvm.dsn
        self.global_conn = self._global_connect()
        super(KVM, self)._initialize_check()

    def _auth_callback(self, credentials, user_data):
        print("in auth callback")
        for credential in credentials:
            if credential[0] == libvirt.VIR_CRED_AUTHNAME:
                credential[4] = self.options.kvm.username
            elif credential[0] == libvirt.VIR_CRED_PASSPHRASE:
                credential[4] = self.options.kvm.password
            else:
                raise CuckooCriticalError("KVM machinery did not recieve an object to inject a username or password into")

        return 0


    def _connect(self):
        """
        return the already-connected single connection handle if set, otherwise set it.
        """
        if self.global_conn == None:
            self.global_conn = self._global_connect()
        return self.global_conn

    def _global_connect(self):
        """Set the single connection handle."""
        print("in global connect")
        try:
            self.auth = [[libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_PASSPHRASE], self._auth_callback, None]
            return libvirt.openAuth(self.dsn, self.auth, 0)
        except libvirt.libvirtError as libvex:
            raise CuckooCriticalError("libvirt returned an exception on connection: %s" % libvex)

    def _disconnect(self, conn):
        """
        Using one global connection we now disconnect in the destructor, ignore requests to disconnect
        """
        pass

    def __del__(self):
        self.global_conn.close()

    def _get_interface(self, label):
        xml = ET.fromstring(self._lookup(label).XMLDesc())
        elem = xml.find("./devices/interface[@type='network']")
        if elem is None:
            return elem
        elem = elem.find("target")
        if elem is None:
            return None

        return elem.attrib["dev"]

    def start(self, label):
        super(KVM, self).start(label)
        if not self.db.view_machine_by_label(label).interface:
            self.db.set_machine_interface(label, self._get_interface(label))
