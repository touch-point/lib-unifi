#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import ssl
import json

from requests import Session, Request
from requests_toolbelt import SSLAdapter

import logging
logging.basicConfig(level=logging.DEBUG)

# workaround to suppress InsecureRequestWarning
# See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
import urllib3
urllib3.disable_warnings()

from . import exceptions


class Controller(object):
    def __init__(self, host='127.0.0.1', port=8443, version='v5'):

        self.host = host
        self.port = port
        self.version = version
        self.version = version
        self.logged_in = False

        self._username = None
        self._password = None
        self._site = None
        self._baseurl = 'https://{}:{}'.format(
            self.host,
            self.port
        )

        self._session = Session()
        self._session.mount(self._baseurl, SSLAdapter(ssl.PROTOCOL_SSLv23))

        self.log = logging.getLogger(__name__)
        self.log.setLevel(logging.DEBUG)


    @property
    def username(self):
        return self._username
    
    @username.setter
    def username(self, value):
        self._username = value

    @property
    def password(self):
        return self._password
    
    @password.setter
    def password(self, value):
        self._password = value
    
    @property
    def site(self):
        if self._site is None:
            return 'default'
        return self._site
    
    @site.setter
    def site(self, value):
        self._site = value

    def _jsondec(self, data):
        obj = data.json()
        if 'meta' in obj:
            if obj['meta']['rc'] != 'ok':
                raise exceptions.APIError(obj['meta']['msg'])
        if 'data' in obj:
            return obj['data']
        return obj

    def _request(self, endpoint, data={}, method='POST'):
        if not self.logged_in:
            self.connect()

        if endpoint == 'login':
            url = '{}/api/{}'.format(self._baseurl, endpoint)
        else:
            url = '{}/api/s/{}/{}'.format(
                self._baseurl,
                self.site,
                endpoint
            )
        
        return self._jsondec(
            self._session.send(
                self._session.prepare_request(
                    Request(
                        method,
                        url,
                        data=json.dumps(data).encode('utf8'),
                        headers={
                            'Content-type': 'application/json'
                        }
                    )                    
                ),
                verify=False
            )
        )
        
    def connect(self, username=None, password=None):
        # Check assigned creds
        if username is None and self.username is None:
            raise exceptions.CredentialsMissing("username not set")

        elif username is not None and self.username is None:
            self.log.debug("connect got username: %s", username)
            # TODO: what is Inspection info: This inspection detects instance attribute definition outside __init__ method
            self.username = username

        if password is None and self.password is None:
            raise exceptions.CredentialsMissing("password not set")

        elif password is not None and self.password is None:
            self.log.debug("connect got password: %s", password)
            self.password = password

        try:
            self.logged_in = True
            return self._request(
                'login',
                {
                    'username': self.username, 
                    'password': self.password
                }
            )
        except exceptions.ConnectionError:
            self.logged_in = False
            return {}

    def disconnect(self):
        self.logged_in = False
        return self._request(
            'logout'
        )

    #****************************************************************
    # Functions to access UniFi controller API routes from here:
    #****************************************************************

    def authorize_guest(self, mac, minutes, up=None, down=None, mbytes=None, ap_mac=None):
        """
        Authorize a guest based on his MAC address.

        Args:
            mac: the guest MAC address
            minutes: duration of the authorization in minutes
            up: up speed allowed in kbps (optional)
            down: down speed allowed in kbps (optional)
            byte: quantity of bytes allowed in MB (optional)
            ap_mac: access point MAC address (UniFi >= 3.x) (optional)
        Returns:
            Response object
        """

        data = {
            'cmd': 'authorize-guest',
            'mac': mac, 
            'minutes': minutes
        }

        if up is not None:
            data['up'] = up
        if down is not None:
            data['down'] = down
        if bytes is not None:
            data['bytes'] = mbytes
        if ap_mac is not None and self.version != 'v2':
            data['ap_mac'] = ap_mac

        return self._request(
            'cmd/stamgr',
            data
        )

    def unauthorize_guest(self, mac):
        """
        Unauthorize a guest based on his MAC address.
        
        mac: the guest MAC address
        """

        return self._request(
            'cmd/stamgr',
            {
                'cmd': 'unauthorize-guest',
                'mac': mac
            }
        )

    def reconnect_sta(self, mac):
        """
        Reconnect a client device

        mac: the guest MAC address
        """

        return self._request(
            'cmd/stamgr',
            {
                'cmd': 'kick-sta',
                'mac': mac
            }
        )

    def block_sta(self, mac):
        """
        Block a client device

        mac: the guest MAC address
        """

        return self._request(
            'cmd/stamgr',
            {
                'cmd': 'block-sta',
                'mac': mac
            }
        )

    def unblock_sta(self, mac):
        """
        Unblock a client device

        mac: the guest MAC address
        """

        return self._request(
            'cmd/stamgr',
            {
                'cmd': 'unblock-sta',
                'mac': mac
            }
        )

    def forget_sta(self, macs):
        """
        Forget one or more client devices

        macs: array of client MAC addresses
        """

        return self._request(
            'cmd/stamgr',
            {
                'cmd': 'forget-sta',
                'macs': macs
            }
        )

    def get_events(self):
        """Return a list of all Events."""

        return self._request(
            'stat/event'
        )

    def get_aps(self):
        """Return a list of all AP:s, with significant information about each."""
        
        return self._request(
            'stat/device',
            {
                '_depth': 2, 
                'test': 0
            }
        )

    def get_clients(self):
        """Return a list of all active clients, with significant information about each."""

        return self._request(
            'stat/sta'
        )

    def get_users(self):
        """Return a list of all known clients, with significant information about each."""

        return self._request(
            'list/user'
        )

    def get_user_groups(self):
        """Return a list of user groups with its rate limiting settings."""

        return self._request(
            'list/usergroup'
        )

    def get_wlan_conf(self):
        """Return a list of configured WLANs with their configuration parameters."""

        return self._request(
            'list/wlanconf'
        )

    def adopt_device(self, mac=None):
        """adopts a given MAC"""
        if mac is None:
            raise exceptions.ValidationError("invalid mac. got:[{}]".format(mac))

        return self._request(
            'cmd/devmgr',
            {
                'cmd': 'adopt',
                'mac': mac
            }
        )

    def update_ap(self, mac=None):
        """updates a device to the latest firmware known to the controller"""
        if mac is None:
            raise exceptions.ValidationError("invalid mac. got:[{}]".format(mac))

        return self._request(
            'cmd/devmgr/upgrade',
            {
                'mac': mac
            }
        )

    def toggle_locate(self, mac=None, enable=True):
        """Triggers the Locate LED flash for a given MAC"""
        if mac is None:
            raise exceptions.ValidationError("invalid mac. got:[{}]".format(mac))

        # We either set or unset locate
        cmd = "set-;ocate"
        if enable is False:
            cmd = "un" + cmd
        return self._request(
            'cmd/devmgr/upgrade',
            {
                'mac': mac,
                'cmd': cmd,
            }

    def forget_device(self, mac=None):
        """forgets a given MAC"""
        if mac is None:
            raise exceptions.ValidationError("invalid mac. got:[{}]".format(mac))

        return self._request(
            'cmd/sitemgr',
            {
                'mac': mac,
                'cmd': 'delete-device',
            }
        )

    def move_device(self, mac=None, full_site_id=None):
        """Moves a give MAC from the site that is $self and onto the site poitned to by 
        full_site_id. No  validation si done on full_site_id"""
        
        if mac is None:
            raise exceptions.ValidationError("invalid mac. got:[{}]".format(mac))

        if full_site_id is None:
            raise exceptions.ValidationError("invalid full_site_id. got:[{}]".format(full_site_id))

        return self._request(
            'cmd/sitemgr',
            {
                'mac': mac,
                'site': full_site_id,
                'cmd': 'move-device',
            }
        )

    def copy_config(self, origin_mac=None, dest_mac=None):
        """copies the config from one MAC to another; both macs must be on the same site"""
        
        if origin_mac is None:
            raise exceptions.ValidationError("invalid origin_mac. got:[{}]".format(origin_mac))

        if dest_mac is None:
            raise exceptions.ValidationError("invalid dest_mac. got:[{}]".format(dest_mac))

        return self._request(
            'cmd/devmgr',
            {
                'mac': dest_mac,
                'origin': origin_mac,
                'cmd': 'clone-config',
            }
        )

    def tag_device(self, macs=None, tag=None):
        """sets the provided tag on the provided macs"""

        if macs is None:
            raise exceptions.ValidationError("invalid macs. got:[{}]".format(macs))

        if tag is None:
            # Appears to support all text. The literal tag `state:update` is represented as
            #   {"member_table":["de:ad:be:ef:"] name":"state:update"}
            raise exceptions.ValidationError("invalid tag. got:[{}]".format(tag))

        return self._request(
            'rest/tag',
            {
                # You can send a list of macs that should get a tag. This API call does NOT appear to
                #   clear any exsting members, only append. E.G.: if mac1 has label $foo, sending the 
                #   tag_device(mac=mac_2, tag=$foo) call will add foo to mac2 and *keep* it on mac1 despit
                #   the call not being made with mac1 in the members that should get $foo
                'member_table': macs,
                'name': tag
            }
        )
    # TODO: find some way to get the device ID from the MAC?
    def configure_ap_radios(self, device_id='', radio_table={}):
        """ TODO: what does this do? I believe that it applys a wifi profile to the AP"""

        # Example device ID is probably the _id in mongo; is there regex i can use to validate that?
        # TODO: find a way to validate input ^
        if device_id is None:
            raise exceptions.ValidationError("invalid device_id. got:[{}]".format(device_id))

        if radio_table is None:
            # Looks like this:
            #   "radio_table":[
            #       {"radio":"ng","name":"wifi0","ht":"20","channel":"auto","tx_power_mode":"auto","antenna_gain":6,"min_rssi_enabled":false,"sens_level_enabled":false,"vwire_enabled":false,"wlangroup_id":"5b974ba3e4b0accb94duw971"},
            #       {"radio":"na","name":"wifi1","ht":"40","channel":"auto","tx_power_mode":"auto","antenna_gain":6,"min_rssi_enabled":false,"hard_noise_floor_enabled":false,"sens_level_enabled":false,"vwire_enabled":false,"wlangroup_id":"5b974ba3e4b0accb94duw972"
            #   ]
            #
            # But when *ONLY* changing the WIFI/SSID config, it looks like this:
            #   "radio_table":[
            #       {"name":"wifi0","radio":"ng","wlangroup_id":"5b974ba3e4b0accb94duw971"},
            #       {"name":"wifi1","radio":"na","wlangroup_id":"5b974ba3e4b0accb94duw971"}
            #   ]}'
            #
            # Where `5b974ba3e4b0accb94duw971` is the mongo _id for the 2.4 and 5 ghz radio SSID/passwords

            # TODO: is there some subset / minimum properties i can validate on?
            raise exceptions.ValidationError("invalid radio_table. got:[{}]".format(radio_table))

        return self._request(
            "rest/device/{}".format(device_id),
            radio_table, method='PUT')
