#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
__author__ = ("Trupti A Shetty, Mohamed Rafeek, Madhan Sankaranarayanan")


DOCUMENTATION = r"""
---
module: rma_workflow_manager
short_description: Manage device replacement workflows in Cisco Catalyst Center.
description:
- The purpose of this workflow is to provide a simple and efficient way for network administrators to initiate RMA requests for faulty network devices. This will streamline the RMA process, reduce manual effort, and improve overall operational efficiency. 
- Implement an RMA (Return Material Authorization) workflow in Cisco Catalyst Center to streamline the process of returning faulty network devices for replacement. 
- RMA provides a workflow to replace routers, switches, and APs.
- Mark devices for replacement and track the replacement workflow.
- For routers and switches, the software image, configuration, and license are restored from the failed device to the replacement device.
- For wireless APs, the replacement device is assigned to the same site, provisioned with primary wireless controller, RF profile, and AP group settings and placed on the same floor map location in Cisco Catalyst Center as the failed AP.

 Before starting RMA:
- The software image version of the faulty device must be imported in the image repository before marking the device for replacement.
- The faulty device must be in an unreachable state.
- If the replacement device onboards Cisco Catalyst Center through Plug and Play (PnP), the faulty device must be assigned to a user-defined site.
- The replacement device must not be in a provisioning state while triggering the RMA workflow.
- The AP RMA feature supports only like-to-like replacement. The replacement AP must have the same model number and PID as the faulty AP.
- The replacement AP must have joined the same Cisco Wireless Controller as the faulty AP.
- A Cisco Mobility Express AP that acts as the wireless controller is not a candidate for the replacement AP.
- The software image version of the faulty AP must be imported in the image repository before marking the device for replacement.
- The faulty device must be assigned to a user-defined site if the replacement device onboards Cisco Catalyst Center through Plug and Play (PnP).
- The replacement AP must not be in provisioning state while triggering the RMA workflow.

Limitations:
- RMA supports replacement of similar devices only. For example, a Cisco Catalyst 3650 switch can be replaced only with another Cisco Catalyst 3650 switch. Also, the platform IDs of the faulty and replacement devices must be the same.
    Model number of cisco device can be fetched using show version command.
- RMA supports replacement of all switches, routers, and Cisco SD-Access devices, except for the following:
    Chassis-based Nexus 7700 Series Switches
    Devices with embedded wireless controllers
    Cisco Wireless Controllers
- RMA supports devices with an external SCEP broker PKI certificate. The PKI certificate is created and authenticated for the replacement device during the RMA workflow. The PKI certificate of the replaced faulty device must be manually deleted from the certificate server.
- RMA workflow supports device replacement only if:
    Faulty and replacement devices have the same extension cards.
    The faulty device is managed by Catalyst Center with a static IP. (RMA is not supported for devices that are managed by Catalyst Center with a DHCP IP.
    The number of ports in both devices does not vary because of the extension cards.
- The replacement device is connected to the same port to which the faulty device was connected.
- Cisco catalyst Center does not support legacy license deployment.
    1.	If the software image installed on the faulty device is earlier than Cisco IOS XE 16.8, then manually install same legacy network license on the replacement device from faulty device.
-  The RMA workflow deregisters the faulty device from Cisco SSM and registers the replacement device with Cisco SSM.
- Cisco DNA Center supports PnP onboarding of the replacement device in a fabric network, except for the following:
    The faulty device is connected to an uplink device using multiple interfaces.
    LAN automation using an overlapping pool.
- If the replacement device onboards through PnP-DHCP functionality, make sure that the device gets the same IP address after every reload and the lease timeout of DHCP is longer than two hours.


version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: 
  - Trupti A Shetty (@TruptiAShetty)
  - A Mohamed Rafeek (@mohamedrafeek)
  - Madhan Sankaranarayanan (@madhansansel)
  
options:
  config_verify:
description: |
    Set to True to verify the Cisco Catalyst Center configuration after applying the playbook config.
    type: bool
    default: False
  state:
description: |
    The desired state of the device replacement workflow.
    type: str
    choices: [ replaced ]
    default: merged
  config:
    description: |
        A list of faulty and replacement device details for initiating the RMA workflow.
         type: list
       elements: dict
       required: True
    suboptions:
     faulty_device_name:
        description: |
               The name or hostname of the faulty device.
               Example: SJ-EN-9300.cisco.local
              type: str
     faulty_device_ip_address:
        description: |
              The ip address of the faulty device.
              Example: 204.192.3.40
              type: str
     faulty_device_serial_number:
        description: |
              The serial number of the faulty device.
              Example: FJC2327U0S2
              type: str
     replacement_device_ip_address:
        description: |
               The ip address of the replacement device.
               Example: : 204.1.2.5      
               type: str
     replacement_device_name:
        description: |
              The name or hostname of the replacement device.
              type: str
             Example: SJ-EN-9300.cisco.local
     replacement_device_serial_number:
       description: |
              The serial number of the replacement device.
              Example: FCW2225C020
              type: str


requirements:
- dnacentersdk >= 2.7.1
- python >= 3.10

notes:
  - SDK Method used is
    devices.get_device_detail 
    device_replacement.mark_device_for_replacement
    device_replacement.deploy_device_replacement_workflow
    device_replacement.unmark_device_for_replacement

  - Path used is
    post /dna/intent/api/v1/device-replacement/workflow
    put  /dna/intent/api/v1/device-replacement/
    post /dna/intent/api/v1/device-replacement/

"""

"""
- User can use either one of the below playbook.
"""

EXAMPLES = r"""
- name: RMA workflow for faulty device replacement
      cisco.dnac.rma_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: replaced
        device_replacements:
         -  faulty_device_name: "SJ-EN-9300.cisco.local"
            replacement_device_name: "SJ-EN-9300.cisco-1.local"
      register: result
"""
 
 

EXAMPLES = r"""
- name: RMA workflow for faulty device replacement
      cisco.dnac.rma_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: replaced
        device_replacements:
         -  faulty_device_ip_address: 204.192.3.40
            replacement_device_ip_address: 204.1.2.5
      register: result
"""



EXAMPLES = r"""
- name: RMA workflow for faulty device replacement
      cisco.dnac.rma_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: replaced
        device_replacements:
         -  faulty_device_serial_number: "FJC2327U0S2"
            replacement_device_serial_number: "FCW2225C020"
      register: result
"""




RETURN = r"""
#Case_1: Marks device for replacement
response_1:
description: |
  Object with API execution details as returned by the Cisco Catalyst Center Python SDK.
  returned: always
  type: object
  sample: >
  {
    "response": {
        "taskId": "string",
        "url": "string"
    },
    "version": "string"
}

#Case_2: Error while marking device for Replacement.
response_2:
description: |
   Object with API execution details as returned by the Cisco Catalyst Center Python SDK.
   returned: always
   type: object
   sample: >
   {
    "response": {
        "taskId": "string",
        "url": "string"
    },
    "version": "string"
}

#Case_3: API to trigger RMA workflow that will replace faulty device with replacement device with same configuration and images
response_3:
description: |
Object with API execution details as returned by the Cisco Catalyst Center Python SDK.
returned: always
   type: object
   sample: >
   {
    "response": {
        "taskId": "string",
        "url": "string"
    },
    "version": "string"
}

#Case_4: RMA workflow failed to replace faulty device with replacement device.
response_3:
description: |
A object with API execution details as returned by the Cisco Catalyst Center Python SDK.
returned: always
   type: object
   sample: >
   {
    "response": {
        "taskId": "string",
        "url": "string"
    },
    "version": "string"
}
"""

import re
import json
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    validate_str
)
from ansible.module_utils.basic import AnsibleModule
import os
import time

class Devicereplacement(DnacBase):
    """Class containing member attributes for rma_workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["merged", "deleted", "replaced"]
        self.payload = module.params
        self.keymap = {}
    
    def pprint(self, jsondata):
        return json.dumps(jsondata, indent=4, separators=(',', ': '))

    def validate_input(self):
        """
            Validate the fields provided in the yml files for RMA workflow.
            Checks the configuration provided in the playbook against a predefined specification
            to ensure it adheres to the expected structure and data types based on input.
            Returns:
            self: An instance of the class with updated attributes:
            - self.msg: A message describing the validation result.
            - self.status: The status of the validation (either 'success' or 'failed').
            - self.validated_config: If successful, a validated version of the 'device_replacements' parameter.
        """

        self.log('Validating the Playbook Yaml File..', "INFO")

        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        device_list = self.payload.get("config")
        device_list = self.camel_to_snake_case(device_list)

        rma_spec = dict(
            faulty_device_name=dict(required=False, type='str'),
            faulty_device_ip_address=dict(required=False, type='str'),
            replacement_device_name=dict(required=False, type='str'),
            replacement_device_ip_address=dict(required=False, type='str'),
            faulty_device_serial_number=dict(required=False, type='str'),
            replacement_device_serial_number=dict(required=False, type='str')
        )

        valid_param, invalid_params = validate_list_of_dicts(device_list, rma_spec)
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
            "\n".join(invalid_params)
        )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        # Remove None values from valid_param
        self.validated_config = []

        for config in valid_param:
            filtered_config = {}
            for key in config:
                if config[key] is not None:
                    filtered_config[key] = config[key]
            self.validated_config.append(filtered_config)

        self.log("Validated config: {0}".format(self.pprint(self.validated_config)), "INFO")
        self.msg = "Successfully validated playbook config params:{0}".format(str(self.validated_config[0]))
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def get_want(self, config):
        """
        Get all faulty and replacement device related information from the playbook needed for the RMA workflow
        in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing configuration information for device replacement.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            Retrieves all device replacement configuration details from the playbook config,
            excluding any fields not directly related to the device replacement workflow.
            The extracted information is stored in the 'want' attribute of the instance for 
            later use in the workflow. It also performs validation on the configuration parameters.
        """

        want = {}
        want["config"] = {}

        for key in config:
            if config[key] is not None:
                want["config"][key] = config[key]
        self.want = want

        # Perform config validation
        self.validate_device_replacement_params()

        if self.status == "failed":
            return self
        
        self.log("Desired State (want): {0}".format(str(self.pprint(self.want))), "INFO")
        return self
        
    def get_have(self):
        """
        Retrieves the current faulty and replacemnet device details from Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method queries Cisco Catalyst Center to check if the specified faulty and
            replacement devices exist. If the devices exist, it retrieves details about them,
            including their IDs and serial numbers. The results are stored in the 'have'
            attribute for later reference in the RMA workflow. If any device is not found
            or an error occurs, it logs the error and updates the status accordingly.
        """

        # Check if 'want' dictionary is valid
        if not self.want or not self.want.get("config"):
            self.msg = "Invalid or missing 'want' dictionary"
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        have = {}
        config = self.want["config"]
        identifier_keys = [
            ("faulty_device_serial_number", "replacement_device_serial_number"),
            ("faulty_device_name", "replacement_device_name"),
            ("faulty_device_ip_address", "replacement_device_ip_address")
        ]

        valid_identifier_found = False

        # Iterate through identifier keys to find valid device combinations
        for faulty_key, replacement_key in identifier_keys:
            faulty_identifier = config.get(faulty_key)
            replacement_identifier = config.get(replacement_key)

            if faulty_identifier and replacement_identifier:
                valid_identifier_found = True

                # Check if faulty device exists
                faulty_device_id, faulty_device_serial_number = self.device_exists(faulty_identifier, faulty_key)
                if faulty_device_id is None or faulty_device_serial_number is None:
                    self.msg = "Faulty device '{0}' not found in Cisco Catalyst Center".format(faulty_identifier)
                    self.log(self.msg, "ERROR")
                    self.status = "failed"
                    return self

                have["faulty_device_id"] = faulty_device_id
                have["faulty_device_serial_number"] = faulty_device_serial_number
                have[faulty_key] = faulty_identifier
                have["faulty_device_exists"] = True
                self.log("Faulty device '{0}' exists in Cisco Catalyst Center".format(faulty_identifier), "INFO")

                # Check if replacement device exists
                replacement_device_id, replacement_device_serial_number = self.device_exists(replacement_identifier, replacement_key)
                if replacement_device_id is None or replacement_device_serial_number is None:
                    self.msg = "Replacement device '{0}' not found in Cisco Catalyst Center".format(replacement_identifier)
                    self.log(self.msg, "ERROR")
                    self.status = "failed"
                    return self

                have["replacement_device_id"] = replacement_device_id
                have["replacement_device_serial_number"] = replacement_device_serial_number
                have[replacement_key] = replacement_identifier
                have["replacement_device_exists"] = True
                self.log("Replacement device '{0}' exists in Cisco Catalyst Center".format(replacement_identifier), "INFO")

                break

        # Check if any valid identifier combination was not found        
        if not valid_identifier_found:
            provided_identifiers = {
                key: value 
                for key, value in config.items() 
                if key in [item for sublist in identifier_keys for item in sublist] and value
            }
            self.msg = "No valid device combination found in config. Provided values in config: {0}".format(provided_identifiers)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.have = have

        if not self.have:
            self.msg = "No valid device information found in config"
            self.log(self.msg, "ERROR")
            self.status = "failed"
        else:
            self.msg = "Successfully validated config params: {0}".format(self.pprint(config))
            self.log("Current State (have): {0}".format(self.pprint(self.have)), "INFO")
            self.log(self.msg, "INFO")
            self.status = "success"

        return self
            
    

    def device_exists(self, identifier, identifier_type):
        """
        Check if a device exists in Cisco Catalyst Center and return its ID and serial number.
        Parameters:
            - self (object): An instance of the class containing the method.
            - identifier (str): The identifier of the device to check.
            - identifier_type (str): The type of identifier (name, ip_address, or serial_number).
        Returns:
            - tuple: A tuple containing the device ID and serial number, or (None, None) if the device is not found or an error occurs.
        Description:
            This method queries Cisco Catalyst Center to check if a specified device exists based on the provided identifier.
            It constructs the appropriate query parameters based on the identifier type (hostname, IP address, or serial number).
            The method then sends a request to Cisco Catalyst Center using the 'get_device_list' function.
            If the device is found and both ID and serial number are available, it returns these as a tuple.
            If the device is not found, lacks necessary information, or if an error occurs during the process,
            it logs an appropriate error message and returns (None, None).
            This method is used to verify the existence of both faulty and replacement devices in the RMA workflow.
        """
        params = {}
        if identifier_type.endswith("_name"):
            params["hostname"] = identifier
        elif identifier_type.endswith("_ip_address"):
            params["managementIpAddress"] = identifier
        elif identifier_type.endswith("_serial_number"):
            params["serialNumber"] = identifier

        try:
            response = self.dnac._exec(
                family="devices",
                function='get_device_list',
                op_modifies=False,
                params=params
            )
            self.log("Received API response from 'get_device_list': {0}".format(self.pprint(response)), "DEBUG")

            if response and response.get('response'):
                if len(response['response']) > 0:
                    device = response['response'][0]
                    device_id = device.get('id')
                    serial_number = device.get('serialNumber')
                    if device_id and serial_number:
                        return device_id, serial_number
                    else:
                        self.log("Device found but ID or serial number missing", "ERROR")
                else:
                    self.log("Device not found in Cisco Catalyst Center", "ERROR")
            else:
                self.log("No valid response received from Cisco Catalyst Center", "ERROR")
        except Exception as e:
            self.log("Exception occurred while querying device: {0}".format(str(e)), "ERROR")

        return None, None
        
     
    def validate_device_replacement_params(self):
        """
        Addtional validation for the faulty and replacemnet device parameters.
        Parameters:
          - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
          - config (dict): A dictionary containing the faulty and replacement device details.
        Returns:
          The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
        Description:
            Example:
                To use this method, create an instance of the class and call 
                'validate_device_replacement_params' on it. If the validation succeeds it return 'success'.
                If it fails, 'self.status' will be 'failed', and
                'self.msg' will describe the validation issues.
                If the validation succeeds, this will allow to go next step, 
                unless this will stop execution based on the fields.
        """
        errormsg = []
        config = self.want.get("config", {})

        # Validate device names
        for name_field in ['faulty_device_name', 'replacement_device_name']:
            if config.get(name_field):
                param_spec = dict(type="str", length_max=255)
                validate_str(config[name_field], param_spec, name_field, errormsg)

        # Validate IP addresses
        for ip_field in ['faulty_device_ip_address', 'replacement_device_ip_address']:
            if config.get(ip_field):
                if not self.is_valid_ipv4(config[ip_field]):
                    errormsg.append("{0}: Invalid IP Address '{1}' in playbook".format(ip_field, config[ip_field]))

        # Validate serial numbers
        serial_regex = re.compile(r'^[A-Z0-9]{11}$')
        for serial_field in ['faulty_device_serial_number', 'replacement_device_serial_number']:
            if config.get(serial_field):
                if not serial_regex.match(config[serial_field]):
                    errormsg.append("{0}: Invalid Serial Number '{1}' in playbook.".format(
                        serial_field, config[serial_field]))

        if errormsg:
            self.msg = "Invalid parameters in playbook config: '{0}' ".format(str("\n".join(errormsg)))
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.msg = "Successfully validated config params:{0}".format(self.pprint(config))
        self.log(self.msg, "INFO")
        self.status = "success"
        return self
     
    def mark_faulty_device_for_replacement(self):
        """
        Mark the faulty device for replacement in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method marks a faulty device for replacement in Cisco Catalyst Center. It performs the following steps:
            - Checks if the faulty device ID is available.
            - Prepares the payload for the API call.
            - Sends a request to Cisco Catalyst Center to mark the device for replacement.
            - Processes the API response and extracts the task ID.
            - Uses the check_rma_task_status method to monitor the task status.
            - Updates the status, msg, and result attributes based on the task result.
            - Handles any exceptions that occur during the process.
        """

        # Check if faulty device ID is available
        if not self.have.get("faulty_device_id"):
            self.log("Faulty device ID is missing", "ERROR")
            self.status = "failed"
            self.msg = "Faulty device ID is missing"
            return self

        import_params = dict(
            payload=[{
                "faultyDeviceId": self.have.get("faulty_device_id"),
                "replacementStatus": "MARKED-FOR-REPLACEMENT"
            }],
        )

        try:
            response = self.dnac._exec(
                family="device_replacement",
                function='mark_device_for_replacement',
                params=import_params
            )
            
            self.log("Received API response from 'mark_device_for_replacement': {0}".format(str(response)), "DEBUG")
            task_id = response.get("response", {}).get("taskId")
            
            task_result = self.check_rma_task_status(
                task_id,
                "Device marked for replacement successfully",
                "Error while marking device for replacement"
            )
            
            self.status = task_result["status"]
            self.msg = task_result["msg"]
            if self.status == "success":
                self.result['changed'] = True

        except Exception as e:
            self.status = "failed"
            self.msg = "Exception occurred while marking device for replacement: {0}".format(str(e))
            self.log(self.msg, "ERROR")

        return self
    
    def get_diff_replaced(self, config):
        """
        Replace a faulty device with a new device in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): Configuration dictionary (not used in this method, but included for consistency).
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method replaces a faulty device with a new device in Cisco Catalyst Center. It performs the following steps:
            - Checks if both faulty and replacement device serial numbers are available.
            - Prepares the payload for the API call.
            - Sends a request to Cisco Catalyst Center to deploy the device replacement workflow.
            - Processes the API response and extracts the task ID.
            - Uses the check_rma_task_status method to monitor the task status.
            - Updates the status, msg, and result attributes based on the task result.
            - If the replacement fails, it attempts to unmark the faulty device:
                - Logs an attempt to unmark the device.
                - Calls the unmark_device_for_replacement method.
                - Combines the original error message with the unmarking result.
            - Handles any exceptions that occur during the process:
                - Logs the exception.
                - Attempts to unmark the device even when an exception occurs.
                - Combines both the original error and the unmarking result in the final message.
            - The final status, message, and result are updated to reflect both the replacement attempt
            and the unmarking process (if applicable).
            This method ensures that even if the device replacement fails or an exception occurs,
            an attempt is made to unmark the faulty device, providing a comprehensive status update.
        """

        # Check if faulty device serial number and replacement device serial number is available.
        if not self.have.get("faulty_device_serial_number") or not self.have.get("replacement_device_serial_number"):
            self.log("Missing faulty device serial number or replacement device serial number", "ERROR")
            self.status = "failed"
            self.msg = "Missing faulty device serial number or replacement device serial number"
            return self

        import_params = dict(
            payload={
                "faultyDeviceSerialNumber": self.have.get("faulty_device_serial_number"),
                "replacementDeviceSerialNumber": self.have.get("replacement_device_serial_number")
            }
        )

        self.log("Replacing device with parameters: {0}".format(self.pprint(import_params)), "INFO")

        try:
            response = self.dnac._exec(
                family="device_replacement",
                function='deploy_device_replacement_workflow',
                op_modifies=True,
                params=import_params
            )
            self.log("Received API response from 'deploy_device_replacement_workflow': {0}".format(self.pprint(response)), "DEBUG")
            
            task_id = response.get("response", {}).get("taskId")
            if not task_id:
                self.status = "failed"
                self.msg = "Task ID not found in the API response"
                self.result['msg'] = self.msg
                return self

            task_result = self.check_rma_task_status(
                task_id,
                "Device replaced successfully",
                "Error while replacing device"
            )
            
            self.status = task_result["status"]
            self.msg = task_result["msg"]
            
            if self.status == "success":
                self.result['changed'] = True
            else:
                replace_error = "Error replacing device: {0}".format(self.msg)
                self.log(replace_error, "ERROR")
                unmark_result = self.unmark_device_for_replacement()
                self.msg = "{0} | Unmarking result: {1}".format(replace_error, unmark_result.msg)
            
            self.result['msg'] = self.msg
            
        except Exception as e:
            replace_error = "Error replacing device: {0}".format(str(e))
            self.log(replace_error, "ERROR")
            self.status = "failed"
            self.msg = replace_error
            self.result['msg'] = replace_error  # Store the original error message
            self.result['response'] = []
            
            # Attempt to unmark the device when an exception occurs
            self.log("Attempting to unmark device after exception", "INFO")
            unmark_result = self.unmark_device_for_replacement()
            self.log("Unmark result after exception: {0}".format(unmark_result.msg), "INFO")
            
            # Combine both error messages
            self.msg = "{0} | Unmarking result: {1}".format(replace_error, unmark_result.msg)
            self.result['msg'] = self.msg  # Update the result message with both errors


        return self
    
     
    def unmark_device_for_replacement(self):
     
        """
        Unmark the faulty device for replacement in Cisco Catalyst Center only when replacing of faulty device to replacement device fails.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method unmarks a faulty device for replacement in Cisco Catalyst Center. It performs the following steps:
            - Checks if the faulty device ID is available.
            - Prepares the payload for the API call.
            - Sends a request to Cisco Catalyst Center to unmark the device for replacement.
            - Processes the API response and extracts the task ID.
            - Uses the check_rma_task_status method to monitor the task status.
            - Updates the status, msg, and result attributes based on the task result.
            - Handles any exceptions that occur during the process.
        """

        # Check if faulty device ID is available
        if not self.have.get("faulty_device_id"):
            self.log("Faulty device ID is missing", "ERROR")
            self.status = "failed"
            self.msg = "Faulty device ID is missing"
            return self

        import_params = dict(
            payload=[{
                "faultyDeviceId": self.have.get("faulty_device_id"),
                "replacementStatus": "MARKED-FOR-REPLACEMENT"
            }],
        )

        try:
            response = self.dnac._exec(
                family="device_replacement",
                function='unmark_device_for_replacement',
                op_modifies=True,
                params=import_params
            )
            self.log("Received API response from 'unmark_device_for_replacement': {0}".format(self.pprint(response)), "DEBUG")
            task_id = response.get("response", {}).get("taskId")
            task_result = self.check_rma_task_status(
                task_id,
                "Device unmarked for replacement successfully",
                "Error while unmarking device for replacement"
            )
            self.status = task_result["status"]
            self.msg = task_result["msg"]
            if self.status == "success":
                self.result['changed'] = True

        except Exception as e:
            self.status = "failed"
            self.msg = "Exception occurred while unmarking device for replacement: {0}".format(str(e))
            self.log(self.msg, "ERROR")
        

        return self
    
    def check_rma_task_status(self, task_id, success_message, error_prefix):
        """
        Check the status of an RMA task in Cisco Catalyst Center.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            task_id (str): The ID of the task to monitor.
            success_message (str): The message to log on successful completion.
            error_prefix (str): The prefix for the error message if the task fails.

        Returns:
            dict: A dictionary containing the status and message of the task result.

        Description:
            This method checks the status of an RMA task in Cisco Catalyst Center. It performs the following steps:
            - Continuously polls the task status using the get_task_details method.
            - Checks if the task has completed successfully or encountered an error.
            - Logs appropriate messages based on the task outcome.
            - Returns a dictionary with the task status and message.
            - Implements a delay between status checks to avoid overwhelming the API.
        """
        while True:
            task_details = self.get_task_details(task_id)
            if not task_details.get("isError") and 'successful' in task_details.get("progress", ""):
                self.log(success_message, "INFO")
                return {"status": "success", "msg": task_details.get("progress")}
            elif task_details.get("isError"):
                error_message = task_details.get("failureReason", f"{error_prefix}: Task failed.")
                self.log(error_message, "ERROR")
                return {"status": "failed", "msg": error_message}
            time.sleep(2)
        

def main():
    """ main entry point for module execution
    """
    # Basic Ansible type check and assigning defaults.
    devicereplacement_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin'},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    'config_verify': {'type': 'bool', "default": False},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'state': {'default': 'merged', 'choices': ['merged', 'deleted', 'replaced']}
                }
    module = AnsibleModule(
        argument_spec=devicereplacement_spec,
        supports_check_mode=True
    )

    ccc_network = Devicereplacement(module)
    state = ccc_network.params.get("state")

    if state not in ccc_network.supported_states:
        ccc_network.status = "invalid"
        ccc_network.msg = "State {0} is invalid".format(state)
        ccc_network.check_return_status()

    ccc_network.validate_input().check_return_status()
    config_verify = ccc_network.params.get("config_verify")

    for config in ccc_network.validated_config:
        ccc_network.reset_values()
        ccc_network.get_want(config).check_return_status()
        ccc_network.get_have().check_return_status()
        ccc_network.mark_faulty_device_for_replacement().check_return_status()
        ccc_network.get_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_network.result)


if __name__ == '__main__':
    main()
