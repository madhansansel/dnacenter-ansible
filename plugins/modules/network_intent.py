
# This module will work for global_pool, Reserve_ip_pool and network

from __future__ import absolute_import, division, print_function

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
    dnac_compare_equality,
)

class DnacNetwork(DnacBase):
    """Class containing member attributes for network intent module"""
    def __init__(self, module):
        super().__init__(module)
        self.have = {}
        self.want = {}
        self.have_reserve = {}
        self.want_reserve = {}
        self.have_net = {}
        self.want_net = {}
        self.have_dev = {}
        self.want_dev = {}
        self.site_id = None


    def validate_input(self):
        """Validate the fields provided in the playbook"""

        temp_spec = {
            "IpAddressSpace": {"type": 'string'},
            "dhcpServerIps": {"type": 'list'},
            "dnsServerIps": {"type": 'list'},
            "gateway": {"type": 'string'},
            "ipPoolCidr": {"type": 'string'},
            "ipPoolName": {"type": 'string'},
            "name": {"type": 'string'},
            "prev_name": {"type": 'string'},
            "type": {"type": "string", \
                "choices": ["Generic", "tunnel", "LAN", "WAN", "management", "service"]},
            "ipv6AddressSpace": {"type": 'bool'},
            "ipv4GlobalPool": {"type": 'string'},
            "ipv4Prefix": {"type": 'bool'},
            "ipv4PrefixLength": {"type": 'string'},
            "ipv4GateWay": {"type": 'string'},
            "ipv4DhcpServers": {"type": 'list'},
            "ipv4DnsServers": {"type": 'list'},
            "ipv6GlobalPool": {"type": 'string'},
            "ipv6Prefix": {"type": 'bool'},
            "ipv6PrefixLength": {"type": 'integer'},
            "ipv6GateWay": {"type": 'string'},
            "ipv6DhcpServers": {"type": 'list'},
            "ipv6DnsServers": {"type": 'list'},
            "ipv4TotalHost": {"type": 'integer'},
            "ipv6TotalHost": {"type": 'integer'},
            "slaacSupport": {"type": 'bool'},
            "siteName": {"type": 'string'},
            "dhcpServer": {"type": 'list'},
            "domainName": {"type": 'string'},
            "primaryIpAddress": {"type": 'string'},
            "secondaryIpAddress": {"type": 'string'},
            "servers" : {"type": 'string', "choices": ["ISE", "AAA"]},
            "ipAddress" : {"type": 'string'},
            "network": {"type": 'string'},
            "protocol": {"type": 'string', "choices": ["RADIUS", "TACACS"]},
            "bannerMessage": {"type": 'string'},
            "retainExistingBanner": {"type": 'bool'},
            "sharedSecret": {"type": 'string'},
            "configureDnacIP": {"type": 'bool'},
            "ipAddresses": {"type": 'list'},
            "timezone": {"type": 'string'},
            "ntpServer": {"type": 'list'}

        }
        if self.config:
            globalPool_details = []
            ReservePool_details = []
            network_details = []
            # Validate template params
            if self.config[0].get("GlobalPoolDetails") is not None:
                globalPool_details = self.config[0].get("GlobalPoolDetails").get("settings").get("ippool")

            if self.config[0].get("ReservePoolDetails") is not None:
                ReservePool_details = [self.config[0].get("ReservePoolDetails")]

            if self.config[0].get("NetworkManagementDetails") is not None:
                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("dhcpServer"):
                    network_details.append({"dhcpServer": self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("dhcpServer")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("dnsServer"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("dnsServer").get("domainName"):
                        network_details.append({"domainName": self.config[0].get("NetworkManagementDetails") \
                            .get("settings").get("dnsServer").get("domainName")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("dnsServer").get("primaryIpAddress"):
                        network_details.append({"primaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("dnsServer").get("primaryIpAddress")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("dnsServer").get("secondaryIpAddress"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("dnsServer").get("secondaryIpAddress")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("clientAndEndpoint_aaa"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("ipAddress"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("ipAddress")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("network"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("network")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("protocol"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("protocol")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("servers"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("servers")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("sharedSecret"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("sharedSecret")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("messageOfTheday"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("messageOfTheday").get("bannerMessage"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("messageOfTheday").get("bannerMessage")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("messageOfTheday").get("retainExistingBanner"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("messageOfTheday").get("retainExistingBanner")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("netflowcollector"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("netflowcollector").get("ipAddress"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("ipAddress")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("netflowcollector").get("port"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("port")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("network_aaa"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("ipAddress"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("ipAddress")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("network"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("network")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("protocol"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("protocol")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("servers"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("servers")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("sharedSecret"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("sharedSecret")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("ntpServer"):
                    network_details.append({"secondaryIpAddress": self.config[0] \
                                  .get("NetworkManagementDetails") \
                            .get("settings").get("ntpServer")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("snmpServer"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("snmpServer").get("configureDnacIP"):
                        network_details.append({"secondaryIpAddress": self.config[0]
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("snmpServer").get("configureDnacIP")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("snmpServer").get("ipAddresses"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("snmpServer").get("ipAddresses")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("syslogServer"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("syslogServer").get("configureDnacIP"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("syslogServer").get("configureDnacIP")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("syslogServer").get("ipAddresses"):
                        network_details.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("syslogServer").get("ipAddresses")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("timezone"):
                    network_details.append({"secondaryIpAddress": self.config[0] \
                                  .get("NetworkManagementDetails") \
                            .get("settings").get("timezone")})

            self.log(str(network_details))
            self.log(str(ReservePool_details))
            self.log(str(network_details))
            playbook_details = globalPool_details + ReservePool_details + network_details
            valid_temp, invalid_params = validate_list_of_dicts(
                playbook_details, temp_spec
            )
            if invalid_params:
                self.msg = "Invalid parameters in playbook: {0}".format(
                    "\n".join(invalid_params)
                )
                self.status = "failed"
                return self
            self.log(str(invalid_params))
            self.validated = valid_temp

            self.log(str(valid_temp))

            self.log(str(self.validated))
            if self.params.get("config")[0].get("GlobalPoolDetails") is not None:
                for temp in self.validated:
                    self.log(str(temp))
                    if self.params.get("config")[0].get("GlobalPoolDetails") \
                            .get("ipPoolName") is not None:
                        self.msg = "missing required arguments: ipPoolName"
                        self.status = "failed"
                        return self

        self.msg = "Successfully validated input"
        self.status = "success"
        return self    

    def get_dnac_params(self, params):
        dnac_params = dict(
            dnac_host=params.get("dnac_host"),
            dnac_port=params.get("dnac_port"),
            dnac_username=params.get("dnac_username"),
            dnac_password=params.get("dnac_password"),
            dnac_verify=params.get("dnac_verify"),
            dnac_debug=params.get("dnac_debug"),
            dnac_log=params.get("dnac_log"),
        )
        return dnac_params


    def requires_update(self, have, want, obj_params):
        current_obj = have
        requested_obj = want
        self.log(str(current_obj))
        self.log(str(requested_obj))

        return any(not dnac_compare_equality(current_obj.get(dnac_param),
                                            requested_obj.get(ansible_param))
                   for(dnac_param, ansible_param) in obj_params)


    def get_pool_id_from_name(self, pool_name):
        pool_id = None
        current_details = None

        try:
            response = self.dnac._exec(
                family = "network_settings",
                function = "get_global_pool",
            )

            if isinstance(response, dict):
                if "response" in response:
                    response = response.get("response")
            self.log(str(response))
            current_details = get_dict_result(response, "ipPoolName", pool_name)
            self.log(str(current_details))
            if current_details:
                pool_id = current_details.get("id")

        except:
            result = None

        return (pool_id, current_details)


    def get_res_id_from_name(self, res_name):
        _id = ""
        current_details = None
        try:
            response = self.dnac._exec(
                family="network_settings",
                function="get_reserve_ip_subpool",
                params={"site_id": self.site_id}
            )

            if isinstance(response, dict):
                if "response" in response:
                    response = response.get("response")
            self.log(str(response))
            current_details = get_dict_result(response, "groupName", res_name)
            self.log(str(current_details))

            _id = current_details.get("id")
        except:
            self.log("except")
            result = None
        return _id


    def get_current_pool(self, pool):
        self.log(str(pool))
        pool_values = {
            "settings": {
                    "ippool": [{
                            "dhcpServerIps": pool.get("dhcpServerIps"),
                            "dnsServerIps": pool.get("dnsServerIps"),
                            "ipPoolCidr": pool.get("ipPoolCidr"),
                            "ipPoolName": pool.get("ipPoolName"),
                            "type": pool.get("type")
                        }]
                }
        }
        self.log(str(pool_values))
        if pool.get("ipv6") is False:
            pool_values.get("settings").get("ippool")[0].update({"IpAddressSpace": "IPv4"})
            self.log("ipv6 - false")
        else:
            pool_values.get("settings").get("ippool")[0].update({"IpAddressSpace": "IPv6"})
            self.log("ipv6 - true")
        if not pool["gateways"]:
            pool_values.get("settings").get("ippool")[0].update({"gateway": ""})
        else:
            pool_values.get("settings").get("ippool")[0] \
                .update({"gateway": pool.get("gateways")[0]})

        return pool_values


    def get_current_res(self, res):
        self.log(str(res))
        res_values = {
            "name": res.get("groupName"),
            "site_id": res.get("siteId"),
        }
        if len(res.get("ipPools")) == 1:

            res_values.update({"ipv4DhcpServers": res.get("ipPools")[0].get("dhcpServerIps")})
            res_values.update({"ipv4DnsServers": res.get("ipPools")[0].get("dnsServerIps")})
            if res.get("ipPools")[0].get("gateways") != []:
                res_values.update({"ipv4GateWay": res.get("ipPools")[0].get("gateways")[0]})
            else:
                res_values.update({"ipv4GateWay": ""})
            res_values.update({"ipv6AddressSpace": "False"})

        elif len(res.get("ipPools")) == 2:
            if res.get("ipPools")[0].get("ipv6") is False:
                res_values.update({"ipv4DhcpServers": res.get("ipPools")[0].get("dhcpServerIps")})
                res_values.update({"ipv4DnsServers": res.get("ipPools")[0].get("dnsServerIps")})
                res_values.update({"ipv4GateWay": res.get("ipPools")[0].get("gateways")[0]})
                res_values.update({"ipv6AddressSpace": "True"})
                res_values.update({"ipv4DhcpServers": res.get("ipPools")[1].get("dhcpServerIps")})
                res_values.update({"ipv4DnsServers": res.get("ipPools")[1].get("dnsServerIps")})
                if res.get("ipPools")[1].get("gateways") != []:
                    res_values.update({"ipv4GateWay": res.get("ipPools")[1].get("gateways")[0]})
                else:
                    res_values.update({"ipv4GateWay": ""})

            elif res.get("ipPools")[1].get("ipv6") is False:
                res_values.update({"ipv4DhcpServers": res.get("ipPools")[1].get("dhcpServerIps")})
                res_values.update({"ipv4DnsServers": res.get("ipPools")[1].get("dnsServerIps")})
                res_values.update({"ipv4GateWay": res.get("ipPools")[1].get("gateways")[0]})
                res_values.update({"ipv6AddressSpace": "True"})
                res_values.update({"ipv4DhcpServers": res.get("ipPools")[0].get("dhcpServerIps")})
                res_values.update({"ipv4DnsServers": res.get("ipPools")[0].get("dnsServerIps")})
                if res.get("ipPools")[0].get("gateways") != []:
                    res_values.update({"ipv4GateWay": res.get("ipPools")[0].get("gateways")[0]})
                else:
                    res_values.update({"ipv4GateWay": ""})
        self.log(str(res_values))
        return res_values


    def get_current_net(self, site_id):
        self.log(str(site_id))
        response = None

        try:
            response = self.dnac._exec(
                family="network_settings",
                function='get_network',
                params={"site_id": site_id}
            )

        except:
            result = None
        self.log(str(response))

        if isinstance(response, dict):
            if "response" in response:
                response = response.get("response")

        dhcp_details = get_dict_result(response, "key", "dhcp.server")
        dns_details = get_dict_result(response, "key", "dns.server")
        snmp_details = get_dict_result(response, "key", "snmp.trap.receiver")
        syslog_details = get_dict_result(response, "key", "syslog.server")
        netflow_details = get_dict_result(response, "key", "netflow.collector")
        ntpserver_details = get_dict_result(response, "key", "ntp.server")
        timezone_details = get_dict_result(response, "key", "timezone.site")
        messageoftheday_details = get_dict_result(response, "key", "banner.setting")
        network_aaa = get_dict_result(response, "key", "aaa.network.server.1")
        network_aaa_pan = get_dict_result(response, "key", "aaa.server.pan.network")
        self.log(str(syslog_details))
        clientAndEndpoint_aaa = get_dict_result(response, "key", "aaa.endpoint.server.1")
        clientAndEndpoint_aaa_pan = get_dict_result(response, "key", "aaa.server.pan.endpoint")

        self.log(str(network_aaa))
        self.log(str(clientAndEndpoint_aaa))

        net_values = {
            "settings": {

                "snmpServer": {
                    "configureDnacIP": snmp_details.get("value")[0].get("configureDnacIP"),
                    "ipAddresses": snmp_details.get("value")[0].get("ipAddresses"),
                },

                "syslogServer": {
                    "configureDnacIP": syslog_details.get("value")[0].get("configureDnacIP"),
                    "ipAddresses": syslog_details.get("value")[0].get("ipAddresses"),
                },

                "netflowcollector": {
                    "ipAddress": netflow_details.get("value")[0].get("ipAddress"),
                    "port": netflow_details.get("value")[0].get("port"),
                    "configureDnacIP": netflow_details.get("value")[0].get("configureDnacIP"),
                },

                "timezone": timezone_details.get("value")[0],

            }
        }
        if dhcp_details != None:
            net_values.get("settings").update({"dhcpServer":  dhcp_details.get("value")})

        if dns_details != None:
            net_values.get("settings").update({"dnsServer": {
                            "domainName": dns_details.get("value")[0].get("domainName"),
                            "primaryIpAddress": dns_details.get("value")[0].get("primaryIpAddress"),
                            "secondaryIpAddress": dns_details.get("value")[0] \
                                .get("secondaryIpAddress")
                        }
                    })

        if ntpserver_details != None:
            net_values.get("settings").update({"ntpServer": ntpserver_details.get("value")})

        if messageoftheday_details != None:
            net_values.get("settings").update({"messageOfTheday": {
                        "bannerMessage": messageoftheday_details \
                            .get("value")[0].get("bannerMessage"),
                        "retainExistingBanner": messageoftheday_details \
                            .get("value")[0].get("retainExistingBanner"),
                        }
                    })

        if network_aaa and network_aaa_pan:
            net_values.get("settings").update({"network_aaa": {
                        "network": network_aaa.get("value")[0].get("ipAddress"),
                        "protocol": network_aaa.get("value")[0].get("protocol"),
                        "ipAddress": network_aaa_pan.get("value")[0]
                        }
                    })

        if clientAndEndpoint_aaa and clientAndEndpoint_aaa_pan:
            net_values.get("settings").update({"clientAndEndpoint_aaa": {
                        "network": clientAndEndpoint_aaa.get("value")[0].get("ipAddress"),
                        "protocol": clientAndEndpoint_aaa.get("value")[0].get("protocol"),
                        "ipAddress": clientAndEndpoint_aaa_pan.get("value")[0],
                        }
                    })
        self.log(str(net_values))
        return net_values

    def get_site_id(self, site_name):

        response = {}
        _id = None
        try:
            response = self.dnac._exec(
                family="sites",
                function='get_site',
                params={"name":site_name},
            )

        except:
            result = None
        self.log(str(response))
        if not response:
            self.log("Invalid site name or site not present")
            self.msg = "Invalid site name or site not present"
            self.status = "failed"
            return self
        else:
            _id = response.get("response")[0].get("id")
        self.log(str(_id))

        return _id


    def pool_exists(self):
        pool_exists = False
        pool_details = {}
        pool_id = None
        response = None
        name = None

      #get it from validated

        name = self.params.get("config")[0].get("GlobalPoolDetails") \
            .get("settings").get("ippool")[0].get("ipPoolName")
        try:

            response = self.dnac._exec(
                family = "network_settings",
                function = "get_global_pool",
            )
            self.log(str(response))
            if isinstance(response, dict):
                if "response" in response:
                    response = response.get("response")

            current_details = get_dict_result(response, "ipPoolName", name)
            self.log(str(name))
            self.log(str(current_details))
            if current_details:
                pool_exists = True
                pool_id = current_details.get("id")
            elif self.config[0].get("GlobalPoolDetails").get("settings") \
                .get("ippool")[0].get("prev_name") is not None:

                pool_id = None
                (pool_id, current_details) = self.get_pool_id_from_name(self.config[0]. \
                    get("GlobalPoolDetails").get("settings").get("ippool")[0].get("prev_name"))

                if pool_id is None:
                    self.msg = "Prev name doesn't exist\n"
                    self.status = "failed"
                    return self
                pool_exists = True
                current_details = get_dict_result(response, "id", pool_id)
                self.log(str(current_details))
            pool_details = self.get_current_pool(current_details)
        except Exception:
            result = None

        self.log(str(pool_details))
        self.log(str(pool_id))
        return (pool_exists, pool_details, pool_id)


    def res_exists(self):
        current_details = None
        res_exists = False
        res_details = None
        res_id = None
        response = None
        site_name = None
        _id = ""
        site_name = self.params.get("config")[0].get("ReservePoolDetails").get("siteName")
        self.log(str(site_name))

        if site_name is not None:
            site_id = self.get_site_id(site_name)
            self.site_id = site_id

        name = self.config[0].get("ReservePoolDetails").get("name")
        prev_name =  self.config[0].get("ReservePoolDetails").get("prev_name")

        if prev_name:
            if not self.params.get("config")[0].get("ReservePoolDetails").get("siteName"):
                self.msg = "Mandatory Parameter siteName required\n"
                self.status = "failed"
                return self
            _id = self.get_res_id_from_name(prev_name)

        self.log(str(_id))
        try:
            response = self.dnac._exec(
                family="network_settings",
                function="get_reserve_ip_subpool",
                params={"siteId":self.site_id}
            )
            if isinstance(response, dict):
                if "response" in response:
                    response = response.get("response")
            self.log(str(response))

            if _id:
                current_details = get_dict_result(response, "id", _id)
            elif name:
                current_details = get_dict_result(response, "groupName", name)

            self.log(str(current_details))

            if current_details:
                res_exists = True
                res_id = current_details.get("id")
                res_details = self.get_current_res(current_details)
        except Exception:
            result = None

        self.log(str(res_details))
        self.log(str(res_id))
        return (res_exists, res_details, res_id)


    def get_have(self):
        pool_exists = False
        pool_details = None
        pool_id = None

        res_exists = False
        res_details = None
        res_id = None

        #checking if the pool is already exists or not

        if self.params.get("config")[0].get("GlobalPoolDetails") is not None:
            have = {}
            (pool_exists, pool_details, pool_id) = self.pool_exists()

            self.log("pool Exists: " + str(pool_exists) + "\n Current Site: " + str(pool_details))

            if pool_exists:
                have["pool_id"] = pool_id
                have["pool_exists"] = pool_exists
                have["pool_details"] = pool_details
                self.log(str(pool_details))

            self.have = have

        if self.params.get("config")[0].get("ReservePoolDetails") is not None:
            have_reserve = {}
            (res_exists, res_details, res_id) = self.res_exists()
            self.log(str(res_exists))
            self.log("Reservation Exists: " + str(res_exists)  \
                + "\n Reserved Pool: " + str(res_details))

            if res_exists:
                have_reserve["res_exists"] = res_exists
                have_reserve["res_id"] = res_id
                have_reserve["res_details"] = res_details
                if have_reserve.get("res_details").get("ipv6AddressSpace") == "False":
                    have_reserve.get("res_details").update({"ipv6AddressSpace": False})
                elif have_reserve.get("res_details").get("ipv6AddressSpace") == "True":
                    have_reserve.get("res_details").update({"ipv6AddressSpace": True})


            self.have_reserve = have_reserve

        if self.params.get("config")[0].get("NetworkManagementDetails") is not None:

            have_net = {}
            site_name = self.params.get("config")[0].get("NetworkManagementDetails").get("siteName")

            if site_name is None:
                self.msg = "Mandatory Parameter siteName missing"
                self.status = "failed"
                return self

            site_id = self.get_site_id(site_name)

            if site_id is None:
                self.msg = "Invalid siteName"
                self.status = "failed"
                return self

            have_net["site_id"] = site_id
            have_net["net_details"] = self.get_current_net(site_id)
            self.log(str(have_net))
            self.have_net = have_net
        self.status = "success"
        return self


    def get_want(self):
        if self.params.get("config")[0].get("GlobalPoolDetails") is not None:
            want = {}
            IpAddressSpace = self.params.get("config")[0] \
                .get("GlobalPoolDetails").get("settings").get("ippool")[0]
            dhcpServerIps = self.params.get("config")[0] \
                .get("GlobalPoolDetails").get("settings").get("ippool")[0]
            dnsServerIps = self.params.get("config")[0] \
                .get("GlobalPoolDetails").get("settings").get("ippool")[0]
            gateway = self.params.get("config")[0] \
                .get("GlobalPoolDetails").get("settings").get("ippool")[0]
            ipPoolCidr = self.params.get("config")[0] \
                .get("GlobalPoolDetails").get("settings").get("ippool")[0]
            ipPoolName = self.params.get("config")[0] \
                .get("GlobalPoolDetails").get("settings").get("ippool")[0]
            _type = self.params.get("config")[0] \
                .get("GlobalPoolDetails").get("settings").get("ippool")[0]

            want = {
                "settings": {
                        "ippool": [{
                                "IpAddressSpace": IpAddressSpace.get("IpAddressSpace"),
                                "dhcpServerIps": dhcpServerIps.get("dhcpServerIps"),
                                "dnsServerIps": dnsServerIps.get("dnsServerIps"),
                                "gateway": gateway.get("gateway"),
                                "ipPoolCidr": ipPoolCidr.get("ipPoolCidr"),
                                "ipPoolName": ipPoolName.get("ipPoolName"),
                                "type": _type.get("type"),
                            }]
                    }
            }
            self.log(str(self.have))
            if not self.have.get("pool_exists"):
                if want.get("settings").get("ippool")[0].get("dhcpServerIps") is None:
                    want.get("settings").get("ippool")[0].update({"dhcpServerIps": []})
                if want.get("settings").get("ippool")[0].get("dnsServerIps") is None:
                    want.get("settings").get("ippool")[0].update({"dnsServerIps": []})
                if want.get("settings").get("ippool")[0].get("IpAddressSpace") is None:
                    want.get("settings").get("ippool")[0].update({"IpAddressSpace": ""})
                if want.get("settings").get("ippool")[0].get("gateway") is None:
                    want.get("settings").get("ippool")[0].update({"gateway": ""})
                if want.get("settings").get("ippool")[0].get("type") is None:
                    want.get("settings").get("ippool")[0].update({"type": "Generic"})

            else:
                if self.have.get("pool_details").get("settings") \
                    .get("ippool")[0].get("IpAddressSpace") == "IPv4":

                    want.get("settings").get("ippool")[0].update({"IpAddressSpace": "IPv4"})
                    self.log("true")

                elif self.have.get("pool_details").get("settings") \
                    .get("ippool")[0].get("IpAddressSpace") == "Ipv6":

                    want.get("settings").get("ippool")[0].update({"IpAddressSpace": "IPv6"})
                    self.log("false")

                want.get("settings").get("ippool")[0].update({"type": self.have. \
                    get("pool_details").get("settings").get("ippool")[0].get("ipPoolType")})
                want.get("settings").get("ippool")[0].update({"ipPoolCidr": \
                    self.have.get("pool_details").get("settings") \
                        .get("ippool")[0].get("ipPoolCidr")})

                if want.get("settings").get("ippool")[0].get("dhcpServerIps") is None and \
                    self.have.get("pool_details").get("settings") \
                        .get("ippool")[0].get("dhcpServerIps") is not None:
                    want.get("settings").get("ippool")[0].update({"dhcpServerIps": \
                        self.have.get("pool_details").get("settings") \
                            .get("ippool")[0].get("dhcpServerIps")})

                if want.get("settings").get("ippool")[0].get("dnsServerIps") is None and \
                    self.have.get("pool_details").get("settings") \
                        .get("ippool")[0].get("dnsServerIps") is not None:

                    want.get("settings").get("ippool")[0].update({"dnsServerIps": \
                        self.have.get("pool_details").get("settings") \
                            .get("ippool")[0].get("dnsServerIps")})

                if want.get("settings").get("ippool")[0].get("gateway") is None and \
                    self.have.get("pool_details").get("settings") \
                        .get("ippool")[0].get("gateway") is not None:

                    want.get("settings").get("ippool")[0].update({"gateway": \
                        self.have.get("pool_details").get("settings") \
                            .get("ippool")[0].get("gateway")})

            self.log(str(want))
            self.want = want

        if self.params.get("config")[0].get("ReservePoolDetails") is not None:

            want_reserve = {
                "name": self.params.get("config")[0].get("ReservePoolDetails").get("name"),
                "type": self.params.get("config")[0].get("ReservePoolDetails").get("type"),
                "ipv6AddressSpace": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv6AddressSpace"),
                "ipv4GlobalPool": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv4GlobalPool"),
                "ipv4Prefix": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv4Prefix"),
                "ipv4PrefixLength": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv4PrefixLength"),
                "ipv4GateWay": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv4GateWay"),
                "ipv4DhcpServers": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv4DhcpServers"),
                "ipv4DnsServers": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv4DnsServers"),
                "ipv4Subnet": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv4Subnet"),
                "ipv6GlobalPool": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv6GlobalPool"),
                "ipv6Prefix": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv6Prefix"),
                "ipv6PrefixLength": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv6PrefixLength"),
                "ipv6GateWay": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv6GateWay"),
                "ipv6DhcpServers": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv6DhcpServers"),
                "ipv6Subnet": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv6Subnet"),
                "ipv6DnsServers": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv6DnsServers"),
                "ipv4TotalHost": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv4TotalHost"),
                "ipv6TotalHost": self.params.get("config")[0] \
                    .get("ReservePoolDetails").get("ipv6TotalHost")
            }

            self.log(str(self.have_reserve))
            if not self.have_reserve:
                if want_reserve.get("type") is None:
                    want_reserve.update({"type": "Generic"})
                if want_reserve.get("ipv4GateWay") is None:
                    want_reserve.update({"ipv4GateWay": ""})
                if want_reserve.get("ipv4DhcpServers") is None:
                    want_reserve.update({"ipv4DhcpServers": []})
                if want_reserve.get("ipv4DnsServers") is None:
                    want_reserve.update({"ipv4DnsServers": []})
                if want_reserve.get("ipv6AddressSpace") is None:
                    want_reserve.update({"ipv6AddressSpace": False})
                if want_reserve.get("slaacSupport") is None:
                    want_reserve.update({"slaacSupport": True})
                if want_reserve.get("ipv4TotalHost") is None:
                    del want_reserve['ipv4TotalHost']
                if want_reserve.get("ipv6Prefix") is None and \
                    want_reserve.get("ipv6AddressSpace") is True:

                    want_reserve.update({"ipv6Prefix": True})
                else:
                    del want_reserve['ipv6Prefix']
                if want_reserve.get("ipv6AddressSpace") is False:
                    if want_reserve.get("ipv6GlobalPool") is None:
                        del want_reserve['ipv6GlobalPool']
                    if want_reserve.get("ipv6PrefixLength") is None:
                        del want_reserve['ipv6PrefixLength']
                    if want_reserve.get("ipv6GateWay") is None:
                        del want_reserve['ipv6GateWay']
                    if want_reserve.get("ipv6DhcpServers") is None:
                        del want_reserve['ipv6DhcpServers']
                    if want_reserve.get("ipv6DnsServers") is None:
                        del want_reserve['ipv6DnsServers']
                    if want_reserve.get("ipv6TotalHost") is None:
                        del want_reserve['ipv6TotalHost']

            else:
                del want_reserve['type']
                del want_reserve['ipv4GlobalPool']
                del want_reserve['ipv4Prefix']
                del want_reserve['ipv4PrefixLength']
                del want_reserve['ipv4TotalHost']
                del want_reserve['ipv4Subnet']

            self.want_reserve = want_reserve

        if self.params.get("config")[0].get("NetworkManagementDetails") is not None:
            self.log(str(self.params))
            want_net = {
                "settings": {
                    "dhcpServer": {

                    },
                    "dnsServer": {

                    },
                    "snmpServer": {

                    },
                    "syslogServer": {

                    },
                    "netflowcollector": {

                    },
                    "ntpServer": {

                    },
                    "timezone": "",
                    "messageOfTheday": {

                    },
                    "network_aaa": {

                    },
                    "clientAndEndpoint_aaa": {

                    }

                }
            }
            if self.params.get("config")[0].get("NetworkManagementDetails") \
                                .get("settings").get("dhcpServer"):
                want_net.get("settings").update({"dhcpServer":
                                self.params.get("config")[0].get("NetworkManagementDetails") \
                                    .get("settings").get("dhcpServer")
                            })
            else:
                del want_net.get("settings")["dhcpServer"]

            if self.params.get("config")[0].get("NetworkManagementDetails") \
                                .get("settings").get("ntpServer"):
                want_net.get("settings").update({"ntpServer":
                                self.params.get("config")[0].get("NetworkManagementDetails") \
                                    .get("settings").get("ntpServer")
                            })
            else:
                del want_net.get("settings")["ntpServer"]

            if self.params.get("config")[0].get("NetworkManagementDetails") \
                                .get("settings").get("timezone"):
                want_net.get("settings")["timezone"] = \
                    self.params.get("config")[0].get("NetworkManagementDetails") \
                                    .get("settings").get("timezone")
            else:
                del want_net.get("settings")["timezone"]

            if self.params.get("config")[0].get("NetworkManagementDetails") \
                                .get("settings").get("dnsServer"):
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                                .get("settings").get("dnsServer").get("domainName"):
                    want_net.get("settings").get("dnsServer").update({
                                "domainName": self.params.get("config")[0] \
                                    .get("NetworkManagementDetails") \
                                    .get("settings").get("dnsServer").get("domainName")
                            })

                if self.params.get("config")[0] \
                                .get("NetworkManagementDetails").get("settings"):
                    want_net.get("settings").get("dnsServer").update({
                                "primaryIpAddress": self.params.get("config")[0] \
                                    .get("NetworkManagementDetails").get("settings") \
                                        .get("dnsServer").get("primaryIpAddress")
                            })

                if self.params.get("config")[0] \
                                .get("NetworkManagementDetails").get("settings") \
                                    .get("dnsServer").get("secondaryIpAddress"):
                    want_net.get("settings").get("dnsServer").update({
                                "secondaryIpAddress": self.params.get("config")[0] \
                                    .get("NetworkManagementDetails").get("settings") \
                                        .get("dnsServer").get("secondaryIpAddress")
                        })
            else:
                del want_net.get("settings")["dnsServer"]

            if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("snmpServer"):
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("snmpServer").get("configureDnacIP"):
                    want_net.get("settings").get("snmpServer").update({
                            "configureDnacIP": self.params.get("config")[0] \
                                .get("NetworkManagementDetails") \
                                .get("settings").get("snmpServer").get("configureDnacIP")
                        })
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("snmpServer").get("ipAddresses"):
                    want_net.get("settings").get("snmpServer").update({
                            "ipAddresses": self.params.get("config")[0] \
                                .get("NetworkManagementDetails") \
                                .get("settings").get("snmpServer").get("ipAddresses")
                        })
            else:
                del want_net.get("settings")["snmpServer"]

            if self.params.get("config")[0].get("NetworkManagementDetails") \
                        .get("settings").get("syslogServer"):
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                        .get("settings").get("syslogServer").get("configureDnacIP"):
                    want_net.get("settings").get("syslogServer").update({
                        "configureDnacIP": self.params.get("config")[0] \
                            .get("NetworkManagementDetails") \
                            .get("settings").get("syslogServer").get("configureDnacIP")
                        })
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                        .get("settings").get("syslogServer").get("ipAddresses"):
                    want_net.get("settings").get("syslogServer").update({
                        "ipAddresses": self.params.get("config")[0] \
                            .get("NetworkManagementDetails") \
                            .get("settings").get("syslogServer").get("ipAddresses")
                        })
            else:
                del want_net.get("settings")["syslogServer"]

            if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector"):
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("ipAddress"):
                    want_net.get("settings").get("netflowcollector").update({
                        "ipAddress": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("ipAddress")
                        })
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("port"):
                    want_net.get("settings").get("netflowcollector").update({
                        "port": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("port")
                        })
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("configureDnacIP"):
                    want_net.get("settings").get("netflowcollector").update({
                        "configureDnacIP": self.params.get("config")[0] \
                            .get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("configureDnacIP")
                        })
            else:
                del want_net.get("settings")["netflowcollector"]

            if self.params.get("config")[0].get("NetworkManagementDetails") \
                        .get("settings").get("messageOfTheday"):
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                        .get("settings").get("messageOfTheday").get("bannerMessage"):
                    want_net.get("settings").get("messageOfTheday").update({
                        "bannerMessage": self.params.get("config")[0] \
                            .get("NetworkManagementDetails") \
                            .get("settings").get("messageOfTheday").get("bannerMessage")
                        })
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                        .get("settings").get("messageOfTheday").get("retainExistingBanner"):
                    want_net.get("settings").get("messageOfTheday").update({
                        "retainExistingBanner": self.params.get("config")[0] \
                            .get("NetworkManagementDetails") \
                            .get("settings").get("messageOfTheday").get("retainExistingBanner")
                        })
            else:
                del want_net.get("settings")["messageOfTheday"]

            if self.params.get("config")[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa"):
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("ipAddress"):
                    want_net.get("settings").get("network_aaa").update({
                        "ipAddress": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("ipAddress")
                        })
                else:
                    if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("servers") == "ISE":
                        self.msg = "missing parameter ipAddress"
                        self.status = "failed"
                        return self
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("network"):
                    want_net.get("settings").get("network_aaa").update({
                        "network": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("network")
                        })
                else:
                    self.msg="missing parameter network"
                    self.status = "failed"
                    return self

                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("protocol"):
                    want_net.get("settings").get("network_aaa").update({
                        "protocol": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("protocol")
                        })
                else:
                    self.msg="missing parameter protocol"
                    self.status = "failed"
                    return self

                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("servers"):
                    want_net.get("settings").get("network_aaa").update({
                        "servers": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("servers")
                        })
                else:
                    self.msg="missing parameter servers"
                    self.status = "failed"
                    return self

                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("sharedSecret"):
                    want_net.get("settings").get("network_aaa").update({
                        "sharedSecret": self.params.get("config")[0] \
                            .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("sharedSecret")
                        })
            else:
                del want_net.get("settings")["network_aaa"]

            if self.params.get("config")[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa"):
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("ipAddress"):
                    want_net.get("settings").get("clientAndEndpoint_aaa").update({
                        "ipAddress": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("ipAddress")
                        })
                else:
                    if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("servers") == "ISE":
                        self. msg="missing parameter ipAddress"
                        self.status = "failed"
                        return self
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("network"):
                    want_net.get("settings").get("clientAndEndpoint_aaa").update({
                        "network": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("network")
                        })
                else:
                    self.msg="missing parameter network"
                    self.status = "failed"
                    return self

                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("protocol"):
                    want_net.get("settings").get("clientAndEndpoint_aaa").update({
                        "protocol": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("protocol")
                        })
                else:
                    self.msg="missing parameter protocol"
                    self.status = "failed"
                    return self
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("servers"):
                    want_net.get("settings").get("clientAndEndpoint_aaa").update({
                        "servers": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("servers")
                        })
                else:
                    self.msg="missing parameter servers"
                    self.status = "failed"
                    return self

                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("sharedSecret"):
                    want_net.get("settings").get("clientAndEndpoint_aaa").update({
                        "sharedSecret": self.params.get("config")[0] \
                            .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("sharedSecret")
                        })
            else:
                del want_net.get("settings")["clientAndEndpoint_aaa"]
            self.log(str(want_net))
            self.want_net = want_net
        self.status = "success"
        return self

    def get_execution_details(self, execid):
        response = None
        self.log(str(execid))
        response = self.dnac._exec(
            family="task",
            function='get_business_api_execution_details',
            params={"execution_id": execid}
        )

        self.log(str(response))

        return response


    def get_diff_merged(self):
        if self.params.get("config")[0].get("GlobalPoolDetails") is not None:

            if not self.params.get("config")[0].get("GlobalPoolDetails") \
                .get("settings").get("ippool")[0].get("ipPoolName"):

                self.msg = "Mandatory Parameter ipPoolName required\n"
                self.status = "failed"
                return self

            pool_updated = False
            pool_created = False

            if self.have.get("pool_exists"):
                self.log("entered")
                obj_params = [
                    ("settings", "settings"),
                ]
                if self.requires_update(self.have.get("pool_details"), self.want, obj_params):
                    self.log("Pool requires update")
                    #Pool Exists
                    pool_params = copy.deepcopy(self.want)
                    pool_params.get("settings").get("ippool")[0] \
                        .update({"id": self.have.get("pool_id")})
                    self.log(str(self.want))
                    self.log(str(pool_params))
                    del pool_params["settings"]["ippool"][0]["IpAddressSpace"]
                    del pool_params["settings"]["ippool"][0]["ipPoolCidr"]
                    del pool_params["settings"]["ippool"][0]["type"]

                    if pool_params.get("settings").get("ippool")[0].get("dhcpServerIps") is None:
                        pool_params.get("settings").get("ippool")[0].update({"dhcpServerIps" : \
                            self.have.get("pool_details").get("settings") \
                                .get("ippool")[0].get("dhcpServerIps")})
                    if pool_params.get("settings").get("ippool")[0].get("dnsServerIps") is None:
                        pool_params.get("settings").get("ippool")[0].update({"dnsServerIps" : \
                            self.have.get("pool_details").get("settings") \
                                .get("ippool")[0].get("dnsServerIps")})
                    if pool_params.get("settings").get("ippool")[0].get("gateway") is None:
                        pool_params.get("settings").get("ippool")[0].update({"gateway" : \
                            self.have.get("pool_details").get("settings") \
                                .get("ippool")[0].get("gateway")})

                    self.log(str(pool_params))
                    self.log(str(self.have))
                    response = self.dnac._exec(
                        family = "network_settings",
                        function = "update_global_pool",
                        params = pool_params,
                    )

                    pool_updated = True
                    self.log(str(pool_updated))

                else:
                    self.log("Pool doesn't requires an update")
                    self.log(str(self.have))
                    self.log(str(self.result))
                    self.result['response'] = self.have.get("settings")
                    self.result['msg'] = "Pool doesn't requires an update"

            else:
                #creating New Pool
                pool_params = self.want
                self.log(str(pool_params))
                response = self.dnac._exec(
                    family="network_settings",
                    function="create_global_pool",
                    params = pool_params,
                )
                self.log("PoolCreated")
                self.log(str(response))
                pool_created = True

            if pool_created or pool_updated:
                if response and isinstance(response, dict):
                    executionid = response.get("executionId")
                    self.log(str(executionid))
                    while True:
                        execution_details = self.get_execution_details(executionid)
                        if execution_details.get("status") == "SUCCESS":
                            self.result['changed'] = True
                            self.result['response'] = execution_details
                            break

                        elif execution_details.get("bapiError"):
                            
                            self.msg=execution_details.get("bapiError")
                            self.status = "failed"
                            return self

                    if pool_updated:
                        self.log("Pool Updated Successfully")
                        self.result['msg'] = "Pool Updated Successfully"
                        self.result['response'].update({"Id": \
                            self.have.get("pool_details").get("id")})

                    elif pool_created:
                        self.log("Pool Created Successfully")
                        (pool_exists, pool_details, pool_id) = self.pool_exists()
                        self.result['response'].update({"Id": pool_id})
                        self.result['response'].update({"Pool Exists": pool_exists})
                        self.result['response'].update({"Pool Details": pool_details})
                        self.result['msg'] = "Pool Created Successfully"
                    else:
                        self.log("Pool doesn't need a update")
                        self.result['msg'] = "Pool doesn't requires an update"
                        self.result['response'].update({"Id": \
                            self.have.get("pool_details").get("id")})

        if self.params.get("config")[0].get("ReservePoolDetails") is not None:

            res_updated = False
            res_created = False
            self.log(str(self.have_reserve.get("res_details")))
            self.log(str(self.want_reserve))
            if self.have_reserve:
                self.log("entered")
                obj_params = [
                    ("name", "name"),
                    ("type", "type"),
                    ("ipv6AddressSpace", "ipv6AddressSpace"),
                    ("ipv4GlobalPool", "ipv4GlobalPool"),
                    ("ipv4Prefix", "ipv4Prefix"),
                    ("ipv4PrefixLength", "ipv4PrefixLength"),
                    ("ipv4GateWay", "ipv4GateWay"),
                    ("ipv4DhcpServers", "ipv4DhcpServers"),
                    ("ipv4DnsServers", "ipv4DnsServers"),
                    ("ipv6GateWay", "ipv6GateWay"),
                    ("ipv6DhcpServers", "ipv6DhcpServers"),
                    ("ipv6DnsServers", "ipv6DnsServers"),
                    ("ipv4TotalHost", "ipv4TotalHost"),
                    ("slaacSupport", "slaacSupport")
                ]

                if self.requires_update(self.have_reserve.get("res_details"), \
                    self.want_reserve, obj_params):

                    self.log("Network requires update")
                    #Pool Exists
                    self.log(str(self.have_reserve))
                    self.log(str(self.want_reserve))

                    res_params = copy.deepcopy(self.want_reserve)
                    res_params.update({"site_id": self.site_id})
                    res_params.update({"id": self.have_reserve.get("res_id")})
                    response = self.dnac._exec(
                        family="network_settings",
                        function="update_reserve_ip_subpool",
                        params=res_params,
                    )

                    self.log("Reservation Updated")
                    self.log(str(response))
                    res_updated = True

                else:
                    self.log("Reserved ip subpool doesn't requires an update")
                    self.result["response"] = self.have_reserve
                    self.result["msg"] = "Reserved ip subpool doesn't requires an update"

            else:
                #creating New Reservation
                res_params = self.want_reserve
                self.log(str(res_params))
                if not self.want_reserve.get("name") or \
                    not self.want_reserve.get("ipv4GlobalPool") or \
                        not self.want_reserve.get("ipv4PrefixLength") or not self.site_id:

                    self.msg="missing parameter name or \
                        ipv4GlobalPool or ipv4PrefixLength or siteName"
                    self.status = "failed"
                    return self  

                res_params.update({"site_id": self.site_id})
                self.log(str(res_params))
                response = self.dnac._exec(
                    family="network_settings",
                    function="reserve_ip_subpool",
                    params=res_params,
                )
                self.log("Reservation Created")
                self.log(str(response))
                res_created = True

            if res_created or res_updated:
                if response and isinstance(response, dict):
                    executionid = response.get("executionId")

                    while True:
                        execution_details = self.get_execution_details(executionid)
                        if execution_details.get("status") == "SUCCESS":
                            self.result['changed'] = True
                            self.result['response'] = execution_details
                            break

                        elif execution_details.get("bapiError"):

                            self.msg = execution_details.get("bapiError")
                            self.status = "failed"
                            return self  

                    if res_updated:
                        self.log("Reserved Ip Subpool Updated Successfully")
                        self.result['msg'] = "Reserved Ip Subpool Updated Successfully"
                        self.result['response'].update({"Reservation details": \
                            self.have.get("res_details")})

                    elif res_created:
                        self.log("Ip Subpool Reservation Created Successfully")
                        (res_exists, res_details, res_id) = self.res_exists()
                        self.result['response'].update({"Reservation Id": res_id})
                        self.result['response'].update({"Reservation Exists": res_exists})
                        self.result['response'].update({"Reservation details": res_details})
                        self.result['msg'] = "Ip Subpool Reservation Created Successfully"
                    else:
                        self.log("Ip Subpool Reservation doesn't need a update")
                        self.result['msg'] = "Ip Subpool Reservation doesn't requires an update"
                        self.result['response'].update({"Reservation details": \
                            self.have.get("res_details")})

        if self.params.get("config")[0].get("NetworkManagementDetails") is not None:

            net_updated = False
            net_created = False
            if self.have_net:
                self.log("entered")
                obj_params = [
                    ("settings", "settings"),
                    ("siteName", "siteName")
                ]
            if self.want_net.get("settings").get("timezone") is None:
                self.msg = "Missing required parameter timezone"
                self.status = "failed"
                return self 

            if self.requires_update(self.have_net.get("net_details"), self.want_net, obj_params):
                self.log("Network update requires")
                self.log(str(self.have_net))
                self.log(str(self.want_net))

                net_params = copy.deepcopy(self.want_net)
                net_params.update({"site_id": self.have_net.get("site_id")})
                response = self.dnac._exec(
                    family="network_settings",
                    function='update_network',
                    params=net_params,
                )

                self.log("Network Updated")
                self.log(str(response))
                net_updated = True

            else:
                self.log("Network doesn't need an update")
                self.result["response"] = self.have_net
                self.result["msg"] = "Network doesn't need an update"
                self.module.exit_json(**self.result)

            if net_updated:
                if response and isinstance(response, dict):
                    executionid = response.get("executionId")
                    self.log(str(response))
                    self.log(str(executionid))

                    while True:
                        execution_details = self.get_execution_details(executionid)
                        if execution_details.get("status") == "SUCCESS":
                            self.result['changed'] = True
                            self.result['response'] = execution_details
                            break

                        elif execution_details.get("bapiError"):

                            self.msg = execution_details.get("bapiError")
                            self.status = "failed"
                            return self

                    if net_updated:
                        self.log("Network has been changed Successfully")
                        self.result['msg'] = "Network Updated successfully"
                        self.result['response'] = self.want_net

                    else:
                        self.log("Pool doesn't need a update")
                        self.result['msg'] = "Network doesn't requires an update"
                        self.result['response'] = self.have_net

    def get_res_id_by_name(self, name):
        _id = None
        try:
            response = self.dnac._exec(
                family="network_settings",
                function="get_reserve_ip_subpool",
                params={"siteId":self.site_id},
            )

            self.log(str(response))

            if isinstance(response, dict):
                if "response" in response:
                    response = response.get("response")
            self.log(str(response))

            current_details = get_dict_result(response, "groupName", name)
            if current_details:
                _id = current_details.get("id")

        except:
            result = None

        return _id


    def get_diff_deleted(self):

        if self.params.get("config")[0].get("ReservePoolDetails") is not None:
            res_exists = self.have_reserve.get("res_exists")
            self.log(str(res_exists))
            _id = None
            if self.want_reserve.get("name"):
                self.log(str(self.want_reserve.get("name")))
                _id = self.get_res_id_by_name(self.want_reserve.get("name"))
            self.log(str(_id))
            if res_exists:
                if not _id:
                    self.msg = "missing or \
                        incorrect parameter reserved pool name"
                    self.status = "failed"
                    return self
                self.log(str(self.have_reserve.get("res_id")))
                response = self.dnac._exec(
                    family="network_settings",
                    function="release_reserve_ip_subpool",
                    params={"id": _id},
                )

                if response and isinstance(response, dict):
                    executionid = response.get("executionId")
                    while True:
                        task_details = self.get_task_details(executionid)
                        if task_details.get("status") == "SUCCESS":
                            self.result['changed'] = True
                            self.result['response'] = task_details
                            self.log(str(response))
                            self.result['msg'] = "Ip subpool reservation released successfully"

                        elif task_details.get("bapiError"):
                            self.msg = task_details.get("bapiError")
                            self.status = "failed"
                            return self

            else:
                self.msg = "Reserved Ip Subpool Not Found"
                self.status = "failed"
                return self

        if self.params.get("config")[0].get("GlobalPoolDetails") is not None:
            pool_exists = self.have.get("pool_exists")

            if pool_exists:
                response = self.dnac._exec(
                    family="network_settings",
                    function="delete_global_ip_pool",
                    params={"id": self.have.get("pool_id")},
                )

                if response and isinstance(response, dict):
                    executionid = response.get("executionId")
                    while True:
                        task_details = self.get_task_details(executionid)
                        if task_details.get("status") == "SUCCESS":
                            self.result['changed'] = True
                            self.result['response'] = task_details
                            self.log(str(response))
                            self.result['msg'] = "Pool deleted successfully"

                        elif task_details.get("bapiError"):
                            self.msg = task_details.get("bapiError")
                            self.status = "failed"
                            return self

            else:
                self.msg = "Pool Not Found"
                self.status = "failed"
                return self

        if self.params.get("config")[0].get("NetworkManagementDetails") is not None:
            self.msg = "No operation available for Delete Network"
            self.status = "failed"
            return self


def main():
    """main entry point for module execution"""

    element_spec ={
        "dnac_host": {"required": True, "type": 'str'},
        "dnac_port": {"type": 'str', "default": '443'},
        "dnac_username": {"type": 'str', "default": 'admin', "aliases": ['user']},
        "dnac_password": {"type": 'str', "no_log": True},
        "dnac_verify": {"type": 'bool', "default": 'True'},
        "dnac_version": {"type": 'str', "default": '2.2.3.3'},
        "dnac_debug": {"type": 'bool', "default": False},
        "dnac_log": {"type": 'bool', "default": False},
        "validate_response_schema": {"type": 'bool', "default": True},
        "config": {"required": True, "type": 'list', "elements": 'dict'},
        "state": {"default": 'merged', "choices": ['merged', 'deleted']},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    dnac_network = DnacNetwork(module)

    dnac_network.validate_input().check_return_status()
    state = dnac_network.params.get("state")
    if state not in dnac_network.supported_states:
        dnac_network.status = "invalid"
        dnac_network.msg = "State {0} is invalid".format(state)
        dnac_network.check_return_status()

    dnac_network.get_have().check_return_status()
    dnac_network.get_want().check_return_status()

    dnac_network.get_diff_state_apply[state]().check_return_status()

    module.exit_json(**dnac_network.result)


if __name__ == "__main__":
    main()
