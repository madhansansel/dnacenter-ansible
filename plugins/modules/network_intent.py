
# This module will work for global_pool, Reserve_ip_pool and network

from ast import And
import copy
import ipaddress
from random import choices
from urllib import response

try:
    from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
        AnsibleArgSpecValidator,
    )
except ImportError:
    ANSIBLE_UTILS_IS_INSTALLED = False
else:
    ANSIBLE_UTILS_IS_INSTALLED = True
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DNACSDK,
    dnac_argument_spec,
    validate_list_of_dicts,
    log,
    get_dict_result,
    dnac_compare_equality,
)
from ansible.module_utils.basic import AnsibleModule

class DnacNetwork:
    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.config = copy.deepcopy(module.params.get("config"))
        self.have = {}
        self.want = {}
        self.have_reserve = {}
        self.want_reserve = {}
        self.have_net = {}
        self.want_net = {}
        self.have_dev = {}
        self.want_dev = {}
        self.site_id = None
        self.validated = []
        dnac_params = self.get_dnac_params(self.params)
        log(str(dnac_params))
        self.dnac = DNACSDK(params=dnac_params)
        self.log = dnac_params.get("dnac_log")

        self.result = dict(changed=False, diff=[], response=[], warnings=[])

    def get_state(self):
        return self.params.get("state")

    def validate_input(self):
        temp_spec = {
            "IpAddressSpace": {"required": False, "type": 'string'},
            "dhcpServerIps": {"required": False, "type": 'list'},
            "dnsServerIps": {"required": False, "type": 'list'},
            "gateway": {"required": False, "type": 'string'},
            "ipPoolCidr": {"required": False, "type": 'string'},
            "ipPoolName": {"required": False, "type": 'string'},
            "name": {"required": False, "type": 'string'},
            "prev_name": {"required": False, "type": 'string'},
            "type": {"required": False, "type": "string", \
                "choices": ["Generic", "tunnel", "LAN", "WAN", "management", "service"]},
            "ipv6AddressSpace": {"required": False, "type": 'string'},
            "ipv4GlobalPool": {"required": False, "type": 'string'},
            "ipv4Prefix": {"required": False, "type": 'string'},
            "ipv4PrefixLength": {"required": False, "type": 'string'},
            "ipv4GateWay": {"required": False, "type": 'string'},
            "ipv4DhcpServers": {"required": False, "type": 'list'},
            "ipv4DnsServers": {"required": False, "type": 'list'},
            "ipv6GlobalPool": {"required": False, "type": 'string'},
            "ipv6Prefix": {"required": False, "type": 'string'},
            "ipv6PrefixLength": {"required": False, "type": 'integer'},
            "ipv6GateWay": {"required": False, "type": 'string'},
            "ipv6DhcpServers": {"required": False, "type": 'list'},
            "ipv6DnsServers": {"required": False, "type": 'list'},
            "ipv4TotalHost": {"required": False, "type": 'integer'},
            "ipv6TotalHost": {"required": False, "type": 'integet'},
            "slaacSupport": {"required": False, "type": 'string'},
            "siteName": {"required": False, "type": 'string'},
            "dhcpServer": {"required": False, "type": 'list'},
            "domainName": {"required": False, "type": 'string'},
            "primaryIpAddress": {"required": False, "type": 'string'},
            "secondaryIpAddress": {"required": False, "type": 'string'},
            "servers" : {"required": False, "type": 'string', "choices": ["ISE", "AAA"]},
            "ipAddress" : {"required": False, "type": 'string'},
            "network": {"required": False, "type": 'string'},
            "protocol": {"required": False, "type": 'string', choices: ["RADIUS", "TACACS"]},
            "bannerMessage": {"required": False, "type": 'string'},
            "retainExistingBanner": {"required": False, "type": 'bool'},
            "sharedSecret": {"required": False, "type": 'string'},
            "configureDnacIP": {"required": False, "type": 'string'},
            "ipAddresses": {"required": False, "type": 'list'},
            "timezone": {"required": False, "type": 'string'},
            "ntpServer": {"required": False, "type": 'list'}

        }
        if self.config:
            msg = None
            temp = []
            temp1 = []
            temp2 = []
            # Validate template params
            if self.config[0].get("GlobalPoolDetails") is not None:
                temp = self.config[0].get("GlobalPoolDetails").get("settings").get("ippool")

            if self.config[0].get("ReservePoolDetails") is not None:
                temp1 = [self.config[0].get("ReservePoolDetails")]

            if self.config[0].get("NetworkManagementDetails") is not None:
                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("dhcpServer"):
                    temp2.append({"dhcpServer": self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("dhcpServer")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("dnsServer"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("dnsServer").get("domainName"):
                        temp2.append({"domainName": self.config[0].get("NetworkManagementDetails") \
                            .get("settings").get("dnsServer").get("domainName")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("dnsServer").get("primaryIpAddress"):
                        temp2.append(self.config[0].get("NetworkManagementDetails") \
                            .get("settings").get("dnsServer").get("primaryIpAddress"))

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("dnsServer").get("secondaryIpAddress"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("dnsServer").get("secondaryIpAddress")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("clientAndEndpoint_aaa"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("ipAddress"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("ipAddress")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("network"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("network")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("protocol"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("protocol")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("servers"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("servers")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("clientAndEndpoint_aaa").get("sharedSecret"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("sharedSecret")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("messageOfTheday"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("messageOfTheday").get("bannerMessage"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("messageOfTheday").get("bannerMessage")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("messageOfTheday").get("retainExistingBanner"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("messageOfTheday").get("retainExistingBanner")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("netflowcollector"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("netflowcollector").get("ipAddress"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("ipAddress")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("netflowcollector").get("port"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("netflowcollector").get("port")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("network_aaa"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("ipAddress"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("ipAddress")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("network"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("network")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("protocol"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("protocol")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("servers"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("servers")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("network_aaa").get("sharedSecret"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("sharedSecret")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("ntpServer"):
                    temp2.append({"secondaryIpAddress": self.config[0] \
                                  .get("NetworkManagementDetails") \
                            .get("settings").get("ntpServer")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("snmpServer"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("snmpServer").get("configureDnacIP"):
                        temp2.append({"secondaryIpAddress": self.config[0]
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("snmpServer").get("configureDnacIP")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("snmpServer").get("ipAddresses"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("snmpServer").get("ipAddresses")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("syslogServer"):
                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("syslogServer").get("configureDnacIP"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("syslogServer").get("configureDnacIP")})

                    if self.config[0].get("NetworkManagementDetails") \
                        .get("settings").get("syslogServer").get("ipAddresses"):
                        temp2.append({"secondaryIpAddress": self.config[0] \
                                      .get("NetworkManagementDetails") \
                            .get("settings").get("syslogServer").get("ipAddresses")})

                if self.config[0].get("NetworkManagementDetails") \
                    .get("settings").get("timezone"):
                    temp2.append({"secondaryIpAddress": self.config[0] \
                                  .get("NetworkManagementDetails") \
                            .get("settings").get("timezone")})

            temp = temp + temp1 + temp2
            valid_temp, invalid_params = validate_list_of_dicts(
                temp, temp_spec
            )
            if invalid_params:
                msg = "Invalid parameters in playbook: {0}".format(
                    "\n".join(invalid_params)
                )
                self.module.fail_json(msg=msg)
            log(str(invalid_params))
            self.validated = valid_temp

            if self.log:
                log(str(valid_temp))
                log(str(self.result))

            log(str(self.validated))
            if self.params.get("config")[0].get("GlobalPoolDetails") is not None:
                for temp in self.validated:
                    log(str(temp))
                    if self.params.get("config")[0].get("GlobalPoolDetails") \
                            .get("ipPoolName") is not None:
                        msg = "missing required arguments: ipPoolName"
                        self.module.fail_json(msg=msg)

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
        log(str(current_obj))
        log(str(requested_obj))

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
            log(str(response))
            current_details = get_dict_result(response, "ipPoolName", pool_name)
            log(str(current_details))
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
            log(str(response))
            current_details = get_dict_result(response, "groupName", res_name)
            log(str(current_details))

            _id = current_details.get("id")
        except:
            log("except")
            result = None
        return _id


    def get_current_pool(self, pool):
        log(str(pool))
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
        log(str(pool_values))
        if pool.get("ipv6") is False:
            pool_values.get("settings").get("ippool")[0].update({"IpAddressSpace": "IPv4"})
            log("ipv6 - false")
        else:
            pool_values.get("settings").get("ippool")[0].update({"IpAddressSpace": "IPv6"})
            log("ipv6 - true")
        if not pool["gateways"]:
            pool_values.get("settings").get("ippool")[0].update({"gateway": ""})
        else:
            pool_values.get("settings").get("ippool")[0] \
                .update({"gateway": pool.get("gateways")[0]})

        return pool_values


    def get_current_res(self, res):
        log(str(res))
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
        log(str(res_values))
        return res_values


    def get_current_net(self, site_id):
        log(str(site_id))
        response = None

        try:
            response = self.dnac._exec(
                family="network_settings",
                function='get_network',
                params={"site_id": site_id}
            )

        except:
            result = None
        log(str(response))

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
        log(str(syslog_details))
        clientAndEndpoint_aaa = get_dict_result(response, "key", "aaa.endpoint.server.1")
        clientAndEndpoint_aaa_pan = get_dict_result(response, "key", "aaa.server.pan.endpoint")

        log(str(network_aaa))
        log(str(clientAndEndpoint_aaa))

        net_values = {
            "settings": {
                # "dhcpServer":  dhcp_details.get("value"),

                # "dnsServer": {
                #     "domainName": dns_details.get("value")[0].get("domainName"),
                #     "primaryIpAddress": dns_details.get("value")[0].get("primaryIpAddress"),
                #     "secondaryIpAddress": dns_details.get("value")[0].get("secondaryIpAddress")
                # },

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

                # "ntpServer": ntpserver_details.get("value"),

                "timezone": timezone_details.get("value")[0],

                # "messageOfTheday": {
                #     "bannerMessage": messageoftheday_details.get("value")[0].get("bannerMessage"),
                #     "retainExistingBanner": messageoftheday_details \
                #       .get("value")[0].get("retainExistingBanner"),
                # },

                # "network_aaa": {
                #     "network": network_aaa.get("value")[0].get("ipAddress"),
                #     "protocol": network_aaa.get("value")[0].get("protocol"),
                #     "ipAddress": network_aaa_pan.get("value")[0]
                # },

                # "clientAndEndpoint_aaa": {
                #     "network": clientAndEndpoint_aaa.get("value")[0].get("ipAddress"),
                #     "protocol": clientAndEndpoint_aaa.get("value")[0].get("protocol"),
                #     "ipAddress": clientAndEndpoint_aaa_pan.get("value")[0],
                # }


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

        # if snmp_details != None:
        #     net_values.get("settings").update({"snmpServer": {
        #                     "configureDnacIP": snmp_details \
        #                       .get("value")[0].get("configureDnacIP"),
        #                     "ipAddresses": snmp_details.get("value")[0].get("ipAddresses"),
        #                 }
        #             })

        # if syslog_details != None:
        #     net_values.get("settings").update({"syslogServer": {
        #                 "configureDnacIP": syslog_details \
        #                   .get("value")[0].get("configureDnacIP"),
        #                 "ipAddresses": syslog_details.get("value")[0].get("ipAddresses"),
        #                 }
        #             })

        # if netflow_details != None:
        #     net_values.get("settings").update({"netflowcollector": {
        #                 "ipAddress": netflow_details.get("value")[0].get("ipAddress"),
        #                 "port": netflow_details.get("value")[0].get("port"),
        #                 "configureDnacIP": netflow_details.get("value")[0].get("configureDnacIP"),
        #                 }
        #             })

        if ntpserver_details != None:
            net_values.get("settings").update({"ntpServer": ntpserver_details.get("value")})

        # if timezone_details != None:
        #     net_values.get("settings").update({"timezone": timezone_details.get("value")[0]})

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
        log(str(net_values))
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
        log(str(response))
        if not response:
            log("Invalid site name or site not present")
            self.result["response"] = []
            self.result["msg"] = "Invalid site name or site not present"
            self.module.fail_json(**self.result)
        else:
            _id = response.get("response")[0].get("id")
        log(str(_id))

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
            log(str(response))
            if isinstance(response, dict):
                if "response" in response:
                    response = response.get("response")

            current_details = get_dict_result(response, "ipPoolName", name)
            log(str(name))
            log(str(current_details))
            if current_details:
                pool_exists = True
                pool_id = current_details.get("id")
            elif self.config[0].get("GlobalPoolDetails").get("settings") \
                .get("ippool")[0].get("prev_name") is not None:

                pool_id = None
                (pool_id, current_details) = self.get_pool_id_from_name(self.config[0]. \
                    get("GlobalPoolDetails").get("settings").get("ippool")[0].get("prev_name"))

                if pool_id is None:
                    msg = "Prev name doesn't exist\n"
                    self.module.fail_json(msg=msg)
                pool_exists = True
                current_details = get_dict_result(response, "id", pool_id)
                log(str(current_details))
            pool_details = self.get_current_pool(current_details)
        except Exception:
            result = None

        log(str(pool_details))
        log(str(pool_id))
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
        log(str(site_name))

        if site_name is not None:
            site_id = self.get_site_id(site_name)
            self.site_id = site_id

        name = self.config[0].get("ReservePoolDetails").get("name")
        prev_name =  self.config[0].get("ReservePoolDetails").get("prev_name")

        if prev_name:
            if not self.params.get("config")[0].get("ReservePoolDetails").get("siteName"):
                msg = "Mandatory Parameter siteName required\n"
                self.module.fail_json(msg=msg)
            _id = self.get_res_id_from_name(prev_name)

        log(str(_id))
        try:
            response = self.dnac._exec(
                family="network_settings",
                function="get_reserve_ip_subpool",
                params={"siteId":self.site_id}
            )
            if isinstance(response, dict):
                if "response" in response:
                    response = response.get("response")
            log(str(response))

            if _id:
                current_details = get_dict_result(response, "id", _id)
            elif name:
                current_details = get_dict_result(response, "groupName", name)

            log(str(current_details))

            if current_details:
                res_exists = True
                res_id = current_details.get("id")
                res_details = self.get_current_res(current_details)
        except Exception:
            result = None

        log(str(res_details))
        log(str(res_id))
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

            if self.log:
                log("pool Exists: " + str(pool_exists) + "\n Current Site: " + str(pool_details))

            if pool_exists:
                have["pool_id"] = pool_id
                have["pool_exists"] = pool_exists
                have["pool_details"] = pool_details
                log(str(pool_details))

            self.have = have

        if self.params.get("config")[0].get("ReservePoolDetails") is not None:
            have_reserve = {}
            (res_exists, res_details, res_id) = self.res_exists()
            log(str(res_exists))
            if self.log:
                log("Reservation Exists: " + str(res_exists)  \
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
                self.module.fail_json(msg="Mandatory Parameter siteName missing", response=[])

            site_id = self.get_site_id(site_name)

            if site_id is None:
                self.module.fail_json(msg="Invalid siteName", response=[])

            have_net["site_id"] = site_id
            have_net["net_details"] = self.get_current_net(site_id)
            log(str(have_net))
            self.have_net = have_net


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
            log(str(self.have))
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
                    log("true")

                elif self.have.get("pool_details").get("settings") \
                    .get("ippool")[0].get("IpAddressSpace") == "Ipv6":

                    want.get("settings").get("ippool")[0].update({"IpAddressSpace": "IPv6"})
                    log("false")

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

            log(str(want))
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

            log(str(self.have_reserve))
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
            log(str(self.params))
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
                        self.module.fail_json(
                            msg="missing parameter ipAddress", response=[]
                        )
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("network"):
                    want_net.get("settings").get("network_aaa").update({
                        "network": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("network")
                        })
                else:
                    self.module.fail_json(
                            msg="missing parameter network", response=[]
                        )
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("protocol"):
                    want_net.get("settings").get("network_aaa").update({
                        "protocol": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("protocol")
                        })
                else:
                    self.module.fail_json(
                            msg="missing parameter protocol", response=[]
                        )
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("servers"):
                    want_net.get("settings").get("network_aaa").update({
                        "servers": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("network_aaa").get("servers")
                        })
                else:
                    self.module.fail_json(
                            msg="missing parameter servers", response=[]
                        )
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
                        self.module.fail_json(
                            msg="missing parameter ipAddress", response=[]
                        )
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("network"):
                    want_net.get("settings").get("clientAndEndpoint_aaa").update({
                        "network": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("network")
                        })
                else:
                    self.module.fail_json(
                            msg="missing parameter network", response=[]
                        )
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("protocol"):
                    want_net.get("settings").get("clientAndEndpoint_aaa").update({
                        "protocol": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("protocol")
                        })
                else:
                    self.module.fail_json(
                            msg="missing parameter protocol", response=[]
                        )
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("servers"):
                    want_net.get("settings").get("clientAndEndpoint_aaa").update({
                        "servers": self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("servers")
                        })
                else:
                    self.module.fail_json(
                            msg="missing parameter servers", response=[]
                        )
                if self.params.get("config")[0].get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("sharedSecret"):
                    want_net.get("settings").get("clientAndEndpoint_aaa").update({
                        "sharedSecret": self.params.get("config")[0] \
                            .get("NetworkManagementDetails") \
                            .get("settings").get("clientAndEndpoint_aaa").get("sharedSecret")
                        })
            else:
                del want_net.get("settings")["clientAndEndpoint_aaa"]
            log(str(want_net))
            self.want_net = want_net


    def get_execution_details(self, execid):
        response = None
        log(str(execid))
        response = self.dnac._exec(
            family="task",
            function='get_business_api_execution_details',
            params={"execution_id": execid}
        )

        if self.log:
            log(str(response))

        return response


    def get_diff_merge(self):
        if self.params.get("config")[0].get("GlobalPoolDetails") is not None:

            if not self.params.get("config")[0].get("GlobalPoolDetails") \
                .get("settings").get("ippool")[0].get("ipPoolName"):

                msg = "Mandatory Parameter ipPoolName required\n"
                self.module.fail_json(msg=msg)

            pool_updated = False
            pool_created = False

            if self.have.get("pool_exists"):
                log("entered")
                obj_params = [
                    ("settings", "settings"),
                ]
                if self.requires_update(self.have.get("pool_details"), self.want, obj_params):
                    log("Pool requires update")
                    #Pool Exists
                    pool_params = copy.deepcopy(self.want)
                    pool_params.get("settings").get("ippool")[0] \
                        .update({"id": self.have.get("pool_id")})
                    log(str(self.want))
                    log(str(pool_params))
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

                    log(str(pool_params))
                    log(str(self.have))
                    response = self.dnac._exec(
                        family = "network_settings",
                        function = "update_global_pool",
                        params = pool_params,
                    )

                    pool_updated = True
                    log(str(pool_updated))

                else:
                    log("Pool doesn't requires an update")
                    log(str(self.have))
                    log(str(self.result))
                    self.result['response'] = self.have.get("settings")
                    self.result['msg'] = "Pool doesn't requires an update"
                    # self.module.exit_json(**self.result)

            else:
                #creating New Pool
                pool_params = self.want
                log(str(pool_params))
                response = self.dnac._exec(
                    family="network_settings",
                    function="create_global_pool",
                    params = pool_params,
                )
                log("PoolCreated")
                log(str(response))
                pool_created = True

            if pool_created or pool_updated:
                if response and isinstance(response, dict):
                    executionid = response.get("executionId")
                    log(str(executionid))
                    while True:
                        execution_details = self.get_execution_details(executionid)
                        if execution_details.get("status") == "SUCCESS":
                            self.result['changed'] = True
                            self.result['response'] = execution_details
                            break

                        elif execution_details.get("bapiError"):

                            self.module.fail_json(msg=execution_details.get("bapiError"),
                                                response=execution_details)
                            break

                    if pool_updated:
                        log("Pool Updated Successfully")
                        self.result['msg'] = "Pool Updated Successfully"
                        self.result['response'].update({"Id": \
                            self.have.get("pool_details").get("id")})

                    elif pool_created:
                        log("Pool Created Successfully")
                        (pool_exists, pool_details, pool_id) = self.pool_exists()
                        self.result['response'].update({"Id": pool_id})
                        self.result['response'].update({"Pool Exists": pool_exists})
                        self.result['response'].update({"Pool Details": pool_details})
                        self.result['msg'] = "Pool Created Successfully"
                    else:
                        log("Pool doesn't need a update")
                        self.result['msg'] = "Pool doesn't requires an update"
                        self.result['response'].update({"Id": \
                            self.have.get("pool_details").get("id")})

        if self.params.get("config")[0].get("ReservePoolDetails") is not None:

            res_updated = False
            res_created = False
            log(str(self.have_reserve.get("res_details")))
            log(str(self.want_reserve))
            if self.have_reserve:
                log("entered")
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

                    log("Network requires update")
                    #Pool Exists
                    log(str(self.have_reserve))
                    log(str(self.want_reserve))

                    res_params = copy.deepcopy(self.want_reserve)
                    res_params.update({"site_id": self.site_id})
                    res_params.update({"id": self.have_reserve.get("res_id")})
                    response = self.dnac._exec(
                        family="network_settings",
                        function="update_reserve_ip_subpool",
                        params=res_params,
                    )

                    log("Reservation Updated")
                    log(str(response))
                    res_updated = True

                else:
                    log("Reserved ip subpool doesn't requires an update")
                    self.result["response"] = self.have_reserve
                    self.result["msg"] = "Reserved ip subpool doesn't requires an update"
                    # self.module.exit_json(**self.result)

            else:
                #creating New Reservation
                res_params = self.want_reserve
                log(str(res_params))
                if not self.want_reserve.get("name") or \
                    not self.want_reserve.get("ipv4GlobalPool") or \
                        not self.want_reserve.get("ipv4PrefixLength") or not self.site_id:

                    self.module.fail_json(msg="missing parameter name or \
                        ipv4GlobalPool or ipv4PrefixLength or siteName", response=[])

                res_params.update({"site_id": self.site_id})
                log(str(res_params))
                response = self.dnac._exec(
                    family="network_settings",
                    function="reserve_ip_subpool",
                    params=res_params,
                )
                log("Reservation Created")
                log(str(response))
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

                            self.module.fail_json(msg=execution_details.get("bapiError"),
                                                response=execution_details)
                            break

                    if res_updated:
                        log("Reserved Ip Subpool Updated Successfully")
                        self.result['msg'] = "Reserved Ip Subpool Updated Successfully"
                        self.result['response'].update({"Reservation details": \
                            self.have.get("res_details")})

                    elif res_created:
                        log("Ip Subpool Reservation Created Successfully")
                        (res_exists, res_details, res_id) = self.res_exists()
                        self.result['response'].update({"Reservation Id": res_id})
                        self.result['response'].update({"Reservation Exists": res_exists})
                        self.result['response'].update({"Reservation details": res_details})
                        self.result['msg'] = "Ip Subpool Reservation Created Successfully"
                    else:
                        log("Ip Subpool Reservation doesn't need a update")
                        self.result['msg'] = "Ip Subpool Reservation doesn't requires an update"
                        self.result['response'].update({"Reservation details": \
                            self.have.get("res_details")})

        if self.params.get("config")[0].get("NetworkManagementDetails") is not None:

            net_updated = False
            net_created = False
            if self.have_net:
                log("entered")
                obj_params = [
                    ("settings", "settings"),
                    ("siteName", "siteName")
                ]
            if self.want_net.get("settings").get("timezone") is None:
                self.module.fail_json(msg="Missing required parameter timezone", response=[])
            # if len(self.have_net) == 10:
            if self.requires_update(self.have_net.get("net_details"), self.want_net, obj_params):
                log("Network update requires")
                log(str(self.have_net))
                log(str(self.want_net))

                net_params = copy.deepcopy(self.want_net)
                net_params.update({"site_id": self.have_net.get("site_id")})
                response = self.dnac._exec(
                    family="network_settings",
                    function='update_network',
                    params=net_params,
                )

                log("Network Updated")
                log(str(response))
                net_updated = True

            else:
                log("Network doesn't need an update")
                self.result["response"] = self.have_net
                self.result["msg"] = "Network doesn't need an update"
                self.module.exit_json(**self.result)

            # else:
            #     #creating New Pool
            #     net_params = self.want_reserve
            #     log(str(res_params))
            #     if self.want_net.get("settings").get("timezone") is None:
            #         self.module.fail_json(msg="Missing required parameter timezone", response=[])

            #     net_params = copy.deepcopy(self.want_net)
            #     net_params.update({"site_id": self.have_net.get("site_id")})
            #     response = self.dnac._exec(
            #             family="network_settings",
            #             function='create_network',
            #             params=net_params,
            #         )

            #     log("Network Updated")
            #     log(str(response))
            #     net_updated = True

            if net_updated:
                if response and isinstance(response, dict):
                    executionid = response.get("executionId")
                    log(str(response))
                    log(str(executionid))

                    while True:
                        execution_details = self.get_execution_details(executionid)
                        if execution_details.get("status") == "SUCCESS":
                            self.result['changed'] = True
                            self.result['response'] = execution_details
                            break

                        elif execution_details.get("bapiError"):

                            self.module.fail_json(msg=execution_details.get("bapiError"),
                                                response=execution_details)
                            break

                    if net_updated:
                        log("Network has been changed Successfully")
                        self.result['msg'] = "Network Updated successfully"
                        self.result['response'] = self.want_net
                    # elif net_created:
                    #     log("Network Created Successfully")
                    #     self.result['msg'] = "Network Created successfully"
                    #     self.result['response'] = self.want_net
                    else:
                        log("Pool doesn't need a update")
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

            log(str(response))

            if isinstance(response, dict):
                if "response" in response:
                    response = response.get("response")
            log(str(response))

            current_details = get_dict_result(response, "groupName", name)
            if current_details:
                _id = current_details.get("id")

        except:
            result = None

        return _id


    def get_diff_delete(self):

        if self.params.get("config")[0].get("ReservePoolDetails") is not None:
            res_exists = self.have_reserve.get("res_exists")
            log(str(res_exists))
            _id = None
            if self.want_reserve.get("name"):
                log(str(self.want_reserve.get("name")))
                _id = self.get_res_id_by_name(self.want_reserve.get("name"))
            log(str(_id))
            if res_exists:
                if not _id:
                    self.module.fail_json(msg="missing or \
                        incorrect parameter reserved pool name", response=[])
                log(str(self.have_reserve.get("res_id")))
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
                            log(str(response))
                            self.result['msg'] = "Ip subpool reservation released successfully"

                        elif task_details.get("bapiError"):
                            self.module.fail_json(msg=task_details.get("bapiError"),
                                                response=task_details)

            else:
                self.module.fail_json(msg="Reserved Ip Subpool Not Found", response=[])

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
                            log(str(response))
                            self.result['msg'] = "Pool deleted successfully"

                        elif task_details.get("bapiError"):
                            self.module.fail_json(msg=task_details.get("bapiError"),
                                                response=task_details)

            else:
                self.module.fail_json(msg="Pool Not Found", response=[])

        if self.params.get("config")[0].get("NetworkManagementDetails") is not None:

            self.module.fail_json(msg="No operation available for Delete Network", response=[])


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

    state = dnac_network.get_state()
    dnac_network.validate_input()

    dnac_network.get_have()
    dnac_network.get_want()

    if state == "merged":
        dnac_network.get_diff_merge()

    elif state == "deleted":
        dnac_network.get_diff_delete()
    log(str(dnac_network.result))

    module.exit_json(**dnac_network.result)


if __name__ == "__main__":
    main()
