#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, first last <email>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    "metadata_version": "0.0.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: flow_analysis
short_description: Manage FlowAnalysis objects of PathTrace
description:
- Returns a summary of all flow analyses stored. Results can be filtered by specified parameters.
- Initiates a new flow analysis with periodic refresh and stat collection options. Returns a request id and a task id to get results and follow progress.
- Returns result of a previously requested flow analysis by its Flow Analysis id.
- Deletes a flow analysis request by its id.
version_added: '1.0'
author: first last (@GitHubID)
options:
    dest_ip:
        description:
        - Destination IP address.
        type: str
    dest_port:
        description:
        - Destination port.
        type: str
    gt_create_time:
        description:
        - Analyses requested after this time.
        type: str
    last_update_time:
        description:
        - Last update time.
        type: str
    limit:
        description:
        - Number of resources returned.
        type: str
    lt_create_time:
        description:
        - Analyses requested before this time.
        type: str
    offset:
        description:
        - Start index of resources returned (1-based).
        type: str
    order:
        description:
        - Order by this field.
        type: str
    periodic_refresh:
        description:
        - Is analysis periodically refreshed?.
        type: bool
    protocol:
        description:
        - Protocol query parameter.
        type: str
    sort_by:
        description:
        - Sort by this field.
        type: str
    source_ip:
        description:
        - Source IP address.
        type: str
    source_port:
        description:
        - Source port.
        type: str
    status:
        description:
        - Status query parameter.
        type: str
    task_id:
        description:
        - Task ID.
        type: str
    controlPath:
        description:
        - FlowAnalysisRequest's controlPath.
        type: bool
    destIP:
        description:
        - FlowAnalysisRequest's destIP.
        type: str
        required: True
    destPort:
        description:
        - FlowAnalysisRequest's destPort.
        type: str
    inclusions:
        description:
        - FlowAnalysisRequest's inclusions (list of strings).
        type: list
    periodicRefresh:
        description:
        - FlowAnalysisRequest's periodicRefresh.
        type: bool
    sourceIP:
        description:
        - FlowAnalysisRequest's sourceIP.
        type: str
        required: True
    sourcePort:
        description:
        - FlowAnalysisRequest's sourcePort.
        type: str
    flow_analysis_id:
        description:
        - Flow analysis request id.
        type: str
        required: True

requirements:
- dnacentersdk
seealso:
# Reference by module name
- module: cisco.dnac.plugins.module_utils.definitions.flow_analysis
# Reference by Internet resource
- name: FlowAnalysis reference
  description: Complete reference of the FlowAnalysis object model.
  link: https://developer.cisco.com/docs/dna-center/api/1-3-3-x
# Reference by Internet resource
- name: FlowAnalysis reference
  description: SDK reference.
  link: https://dnacentersdk.readthedocs.io/en/latest/api/api.html#v2-1-1-summary
"""

EXAMPLES = r"""
"""

RETURN = r"""
data_0:
    description: Returns a summary of all flow analyses stored. Results can be filtered by specified parameters.
    returned: success,changed,always
    type: dict
    contains:
        response:
            description: Response, property of the response body (list of objects).
            returned: success,changed,always
            type: list
            contains:
                controlPath:
                    description: It is the flow analysis's controlPath.
                    returned: success,changed,always
                    type: bool
                    sample: false
                createTime:
                    description: It is the flow analysis's createTime.
                    returned: success,changed,always
                    type: int
                    sample: 0
                destIP:
                    description: It is the flow analysis's destIP.
                    returned: success,changed,always
                    type: str
                    sample: '<destip>'
                destPort:
                    description: It is the flow analysis's destPort.
                    returned: success,changed,always
                    type: str
                    sample: '<destport>'
                failureReason:
                    description: It is the flow analysis's failureReason.
                    returned: success,changed,always
                    type: str
                    sample: '<failurereason>'
                id:
                    description: It is the flow analysis's id.
                    returned: success,changed,always
                    type: str
                    sample: '478012'
                inclusions:
                    description: It is the flow analysis's inclusions.
                    returned: success,changed,always
                    type: list
                lastUpdateTime:
                    description: It is the flow analysis's lastUpdateTime.
                    returned: success,changed,always
                    type: int
                    sample: 0
                periodicRefresh:
                    description: It is the flow analysis's periodicRefresh.
                    returned: success,changed,always
                    type: bool
                    sample: false
                protocol:
                    description: It is the flow analysis's protocol.
                    returned: success,changed,always
                    type: str
                    sample: '<protocol>'
                sourceIP:
                    description: It is the flow analysis's sourceIP.
                    returned: success,changed,always
                    type: str
                    sample: '<sourceip>'
                sourcePort:
                    description: It is the flow analysis's sourcePort.
                    returned: success,changed,always
                    type: str
                    sample: '<sourceport>'
                status:
                    description: It is the flow analysis's status.
                    returned: success,changed,always
                    type: str
                    sample: '<status>'

        version:
            description: Version, property of the response body.
            returned: success,changed,always
            type: str
            sample: '1.0'

data_1:
    description: Initiates a new flow analysis with periodic refresh and stat collection options. Returns a request id and a task id to get results and follow progress.
    returned: success,changed,always
    type: dict
    contains:
        response:
            description: FlowAnalysisRequest's response.
            returned: success,changed,always
            type: dict
            contains:
                flowAnalysisId:
                    description: It is the flow analysis's flowAnalysisId.
                    returned: success,changed,always
                    type: str
                    sample: '<flowanalysisid>'
                taskId:
                    description: It is the flow analysis's taskId.
                    returned: success,changed,always
                    type: str
                    sample: 'aeed229047801200e0ef563dbb9a71c2'
                url:
                    description: It is the flow analysis's url.
                    returned: success,changed,always
                    type: str
                    sample: '<url>'

        version:
            description: FlowAnalysisRequest's version.
            returned: success,changed,always
            type: str
            sample: '1.0'

data_2:
    description: Returns result of a previously requested flow analysis by its Flow Analysis id.
    returned: success,changed,always
    type: dict
    contains:
        response:
            description: Response, property of the response body.
            returned: success,changed,always
            type: dict
            contains:
                detailedStatus:
                    description: It is the flow analysis's detailedStatus.
                    returned: success,changed,always
                    type: dict
                    contains:
                        aclTraceCalculation:
                            description: It is the flow analysis's aclTraceCalculation.
                            returned: success,changed,always
                            type: str
                            sample: '<acltracecalculation>'
                        aclTraceCalculationFailureReason:
                            description: It is the flow analysis's aclTraceCalculationFailureReason.
                            returned: success,changed,always
                            type: str
                            sample: '<acltracecalculationfailurereason>'

                lastUpdate:
                    description: It is the flow analysis's lastUpdate.
                    returned: success,changed,always
                    type: str
                    sample: '<lastupdate>'
                networkElements:
                    description: It is the flow analysis's networkElements.
                    returned: success,changed,always
                    type: list
                    contains:
                        accuracyList:
                            description: It is the flow analysis's accuracyList.
                            returned: success,changed,always
                            type: list
                            contains:
                                percent:
                                    description: It is the flow analysis's percent.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                reason:
                                    description: It is the flow analysis's reason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<reason>'

                        detailedStatus:
                            description: It is the flow analysis's detailedStatus.
                            returned: success,changed,always
                            type: dict
                            contains:
                                aclTraceCalculation:
                                    description: It is the flow analysis's aclTraceCalculation.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<acltracecalculation>'
                                aclTraceCalculationFailureReason:
                                    description: It is the flow analysis's aclTraceCalculationFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<acltracecalculationfailurereason>'

                        deviceStatistics:
                            description: It is the flow analysis's deviceStatistics.
                            returned: success,changed,always
                            type: dict
                            contains:
                                cpuStatistics:
                                    description: It is the flow analysis's cpuStatistics.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        fiveMinUsageInPercentage:
                                            description: It is the flow analysis's fiveMinUsageInPercentage.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        fiveSecsUsageInPercentage:
                                            description: It is the flow analysis's fiveSecsUsageInPercentage.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        oneMinUsageInPercentage:
                                            description: It is the flow analysis's oneMinUsageInPercentage.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                memoryStatistics:
                                    description: It is the flow analysis's memoryStatistics.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        memoryUsage:
                                            description: It is the flow analysis's memoryUsage.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        totalMemory:
                                            description: It is the flow analysis's totalMemory.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0


                        deviceStatsCollection:
                            description: It is the flow analysis's deviceStatsCollection.
                            returned: success,changed,always
                            type: str
                            sample: '<devicestatscollection>'
                        deviceStatsCollectionFailureReason:
                            description: It is the flow analysis's deviceStatsCollectionFailureReason.
                            returned: success,changed,always
                            type: str
                            sample: '<devicestatscollectionfailurereason>'
                        egressPhysicalInterface:
                            description: It is the flow analysis's egressPhysicalInterface.
                            returned: success,changed,always
                            type: dict
                            contains:
                                aclAnalysis:
                                    description: It is the flow analysis's aclAnalysis.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclName:
                                            description: It is the flow analysis's aclName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<aclname>'
                                        matchingAces:
                                            description: It is the flow analysis's matchingAces.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                ace:
                                                    description: It is the flow analysis's ace.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<ace>'
                                                matchingPorts:
                                                    description: It is the flow analysis's matchingPorts.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ports:
                                                            description: It is the flow analysis's ports.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                destPorts:
                                                                    description: It is the flow analysis's destPorts.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                sourcePorts:
                                                                    description: It is the flow analysis's sourcePorts.
                                                                    returned: success,changed,always
                                                                    type: list

                                                        protocol:
                                                            description: It is the flow analysis's protocol.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<protocol>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        result:
                                            description: It is the flow analysis's result.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<result>'

                                id:
                                    description: It is the flow analysis's id.
                                    returned: success,changed,always
                                    type: str
                                    sample: '478012'
                                interfaceStatistics:
                                    description: It is the flow analysis's interfaceStatistics.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        adminStatus:
                                            description: It is the flow analysis's adminStatus.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<adminstatus>'
                                        inputPackets:
                                            description: It is the flow analysis's inputPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueCount:
                                            description: It is the flow analysis's inputQueueCount.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueDrops:
                                            description: It is the flow analysis's inputQueueDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueFlushes:
                                            description: It is the flow analysis's inputQueueFlushes.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueMaxDepth:
                                            description: It is the flow analysis's inputQueueMaxDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputRatebps:
                                            description: It is the flow analysis's inputRatebps.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        operationalStatus:
                                            description: It is the flow analysis's operationalStatus.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<operationalstatus>'
                                        outputDrop:
                                            description: It is the flow analysis's outputDrop.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputPackets:
                                            description: It is the flow analysis's outputPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputQueueCount:
                                            description: It is the flow analysis's outputQueueCount.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputQueueDepth:
                                            description: It is the flow analysis's outputQueueDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputRatebps:
                                            description: It is the flow analysis's outputRatebps.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                interfaceStatsCollection:
                                    description: It is the flow analysis's interfaceStatsCollection.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<interfacestatscollection>'
                                interfaceStatsCollectionFailureReason:
                                    description: It is the flow analysis's interfaceStatsCollectionFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<interfacestatscollectionfailurereason>'
                                name:
                                    description: It is the flow analysis's name.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<name>'
                                pathOverlayInfo:
                                    description: It is the flow analysis's pathOverlayInfo.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        controlPlane:
                                            description: It is the flow analysis's controlPlane.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<controlplane>'
                                        dataPacketEncapsulation:
                                            description: It is the flow analysis's dataPacketEncapsulation.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<datapacketencapsulation>'
                                        destIp:
                                            description: It is the flow analysis's destIp.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<destip>'
                                        destPort:
                                            description: It is the flow analysis's destPort.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<destport>'
                                        protocol:
                                            description: It is the flow analysis's protocol.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<protocol>'
                                        sourceIp:
                                            description: It is the flow analysis's sourceIp.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<sourceip>'
                                        sourcePort:
                                            description: It is the flow analysis's sourcePort.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<sourceport>'
                                        vxlanInfo:
                                            description: It is the flow analysis's vxlanInfo.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                dscp:
                                                    description: It is the flow analysis's dscp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<dscp>'
                                                vnid:
                                                    description: It is the flow analysis's vnid.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<vnid>'


                                qosStatistics:
                                    description: It is the flow analysis's qosStatistics.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        classMapName:
                                            description: It is the flow analysis's classMapName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<classmapname>'
                                        dropRate:
                                            description: It is the flow analysis's dropRate.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        numBytes:
                                            description: It is the flow analysis's numBytes.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        numPackets:
                                            description: It is the flow analysis's numPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        offeredRate:
                                            description: It is the flow analysis's offeredRate.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueBandwidthbps:
                                            description: It is the flow analysis's queueBandwidthbps.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<queuebandwidthbps>'
                                        queueDepth:
                                            description: It is the flow analysis's queueDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueNoBufferDrops:
                                            description: It is the flow analysis's queueNoBufferDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueTotalDrops:
                                            description: It is the flow analysis's queueTotalDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                qosStatsCollection:
                                    description: It is the flow analysis's qosStatsCollection.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<qosstatscollection>'
                                qosStatsCollectionFailureReason:
                                    description: It is the flow analysis's qosStatsCollectionFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<qosstatscollectionfailurereason>'
                                usedVlan:
                                    description: It is the flow analysis's usedVlan.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<usedvlan>'
                                vrfName:
                                    description: It is the flow analysis's vrfName.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<vrfname>'

                        egressVirtualInterface:
                            description: It is the flow analysis's egressVirtualInterface.
                            returned: success,changed,always
                            type: dict
                            contains:
                                aclAnalysis:
                                    description: It is the flow analysis's aclAnalysis.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclName:
                                            description: It is the flow analysis's aclName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<aclname>'
                                        matchingAces:
                                            description: It is the flow analysis's matchingAces.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                ace:
                                                    description: It is the flow analysis's ace.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<ace>'
                                                matchingPorts:
                                                    description: It is the flow analysis's matchingPorts.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ports:
                                                            description: It is the flow analysis's ports.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                destPorts:
                                                                    description: It is the flow analysis's destPorts.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                sourcePorts:
                                                                    description: It is the flow analysis's sourcePorts.
                                                                    returned: success,changed,always
                                                                    type: list

                                                        protocol:
                                                            description: It is the flow analysis's protocol.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<protocol>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        result:
                                            description: It is the flow analysis's result.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<result>'

                                id:
                                    description: It is the flow analysis's id.
                                    returned: success,changed,always
                                    type: str
                                    sample: '478012'
                                interfaceStatistics:
                                    description: It is the flow analysis's interfaceStatistics.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        adminStatus:
                                            description: It is the flow analysis's adminStatus.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<adminstatus>'
                                        inputPackets:
                                            description: It is the flow analysis's inputPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueCount:
                                            description: It is the flow analysis's inputQueueCount.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueDrops:
                                            description: It is the flow analysis's inputQueueDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueFlushes:
                                            description: It is the flow analysis's inputQueueFlushes.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueMaxDepth:
                                            description: It is the flow analysis's inputQueueMaxDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputRatebps:
                                            description: It is the flow analysis's inputRatebps.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        operationalStatus:
                                            description: It is the flow analysis's operationalStatus.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<operationalstatus>'
                                        outputDrop:
                                            description: It is the flow analysis's outputDrop.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputPackets:
                                            description: It is the flow analysis's outputPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputQueueCount:
                                            description: It is the flow analysis's outputQueueCount.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputQueueDepth:
                                            description: It is the flow analysis's outputQueueDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputRatebps:
                                            description: It is the flow analysis's outputRatebps.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                interfaceStatsCollection:
                                    description: It is the flow analysis's interfaceStatsCollection.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<interfacestatscollection>'
                                interfaceStatsCollectionFailureReason:
                                    description: It is the flow analysis's interfaceStatsCollectionFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<interfacestatscollectionfailurereason>'
                                name:
                                    description: It is the flow analysis's name.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<name>'
                                pathOverlayInfo:
                                    description: It is the flow analysis's pathOverlayInfo.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        controlPlane:
                                            description: It is the flow analysis's controlPlane.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<controlplane>'
                                        dataPacketEncapsulation:
                                            description: It is the flow analysis's dataPacketEncapsulation.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<datapacketencapsulation>'
                                        destIp:
                                            description: It is the flow analysis's destIp.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<destip>'
                                        destPort:
                                            description: It is the flow analysis's destPort.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<destport>'
                                        protocol:
                                            description: It is the flow analysis's protocol.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<protocol>'
                                        sourceIp:
                                            description: It is the flow analysis's sourceIp.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<sourceip>'
                                        sourcePort:
                                            description: It is the flow analysis's sourcePort.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<sourceport>'
                                        vxlanInfo:
                                            description: It is the flow analysis's vxlanInfo.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                dscp:
                                                    description: It is the flow analysis's dscp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<dscp>'
                                                vnid:
                                                    description: It is the flow analysis's vnid.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<vnid>'


                                qosStatistics:
                                    description: It is the flow analysis's qosStatistics.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        classMapName:
                                            description: It is the flow analysis's classMapName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<classmapname>'
                                        dropRate:
                                            description: It is the flow analysis's dropRate.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        numBytes:
                                            description: It is the flow analysis's numBytes.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        numPackets:
                                            description: It is the flow analysis's numPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        offeredRate:
                                            description: It is the flow analysis's offeredRate.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueBandwidthbps:
                                            description: It is the flow analysis's queueBandwidthbps.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<queuebandwidthbps>'
                                        queueDepth:
                                            description: It is the flow analysis's queueDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueNoBufferDrops:
                                            description: It is the flow analysis's queueNoBufferDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueTotalDrops:
                                            description: It is the flow analysis's queueTotalDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                qosStatsCollection:
                                    description: It is the flow analysis's qosStatsCollection.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<qosstatscollection>'
                                qosStatsCollectionFailureReason:
                                    description: It is the flow analysis's qosStatsCollectionFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<qosstatscollectionfailurereason>'
                                usedVlan:
                                    description: It is the flow analysis's usedVlan.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<usedvlan>'
                                vrfName:
                                    description: It is the flow analysis's vrfName.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<vrfname>'

                        flexConnect:
                            description: It is the flow analysis's flexConnect.
                            returned: success,changed,always
                            type: dict
                            contains:
                                authentication:
                                    description: It is the flow analysis's authentication.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<authentication>'
                                dataSwitching:
                                    description: It is the flow analysis's dataSwitching.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<dataswitching>'
                                egressAclAnalysis:
                                    description: It is the flow analysis's egressAclAnalysis.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclName:
                                            description: It is the flow analysis's aclName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<aclname>'
                                        matchingAces:
                                            description: It is the flow analysis's matchingAces.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                ace:
                                                    description: It is the flow analysis's ace.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<ace>'
                                                matchingPorts:
                                                    description: It is the flow analysis's matchingPorts.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ports:
                                                            description: It is the flow analysis's ports.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                destPorts:
                                                                    description: It is the flow analysis's destPorts.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                sourcePorts:
                                                                    description: It is the flow analysis's sourcePorts.
                                                                    returned: success,changed,always
                                                                    type: list

                                                        protocol:
                                                            description: It is the flow analysis's protocol.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<protocol>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        result:
                                            description: It is the flow analysis's result.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<result>'

                                ingressAclAnalysis:
                                    description: It is the flow analysis's ingressAclAnalysis.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclName:
                                            description: It is the flow analysis's aclName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<aclname>'
                                        matchingAces:
                                            description: It is the flow analysis's matchingAces.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                ace:
                                                    description: It is the flow analysis's ace.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<ace>'
                                                matchingPorts:
                                                    description: It is the flow analysis's matchingPorts.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ports:
                                                            description: It is the flow analysis's ports.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                destPorts:
                                                                    description: It is the flow analysis's destPorts.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                sourcePorts:
                                                                    description: It is the flow analysis's sourcePorts.
                                                                    returned: success,changed,always
                                                                    type: list

                                                        protocol:
                                                            description: It is the flow analysis's protocol.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<protocol>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        result:
                                            description: It is the flow analysis's result.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<result>'

                                wirelessLanControllerId:
                                    description: It is the flow analysis's wirelessLanControllerId.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<wirelesslancontrollerid>'
                                wirelessLanControllerName:
                                    description: It is the flow analysis's wirelessLanControllerName.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<wirelesslancontrollername>'

                        id:
                            description: It is the flow analysis's id.
                            returned: success,changed,always
                            type: str
                            sample: '478012'
                        ingressPhysicalInterface:
                            description: It is the flow analysis's ingressPhysicalInterface.
                            returned: success,changed,always
                            type: dict
                            contains:
                                aclAnalysis:
                                    description: It is the flow analysis's aclAnalysis.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclName:
                                            description: It is the flow analysis's aclName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<aclname>'
                                        matchingAces:
                                            description: It is the flow analysis's matchingAces.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                ace:
                                                    description: It is the flow analysis's ace.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<ace>'
                                                matchingPorts:
                                                    description: It is the flow analysis's matchingPorts.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ports:
                                                            description: It is the flow analysis's ports.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                destPorts:
                                                                    description: It is the flow analysis's destPorts.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                sourcePorts:
                                                                    description: It is the flow analysis's sourcePorts.
                                                                    returned: success,changed,always
                                                                    type: list

                                                        protocol:
                                                            description: It is the flow analysis's protocol.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<protocol>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        result:
                                            description: It is the flow analysis's result.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<result>'

                                id:
                                    description: It is the flow analysis's id.
                                    returned: success,changed,always
                                    type: str
                                    sample: '478012'
                                interfaceStatistics:
                                    description: It is the flow analysis's interfaceStatistics.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        adminStatus:
                                            description: It is the flow analysis's adminStatus.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<adminstatus>'
                                        inputPackets:
                                            description: It is the flow analysis's inputPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueCount:
                                            description: It is the flow analysis's inputQueueCount.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueDrops:
                                            description: It is the flow analysis's inputQueueDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueFlushes:
                                            description: It is the flow analysis's inputQueueFlushes.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueMaxDepth:
                                            description: It is the flow analysis's inputQueueMaxDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputRatebps:
                                            description: It is the flow analysis's inputRatebps.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        operationalStatus:
                                            description: It is the flow analysis's operationalStatus.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<operationalstatus>'
                                        outputDrop:
                                            description: It is the flow analysis's outputDrop.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputPackets:
                                            description: It is the flow analysis's outputPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputQueueCount:
                                            description: It is the flow analysis's outputQueueCount.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputQueueDepth:
                                            description: It is the flow analysis's outputQueueDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputRatebps:
                                            description: It is the flow analysis's outputRatebps.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                interfaceStatsCollection:
                                    description: It is the flow analysis's interfaceStatsCollection.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<interfacestatscollection>'
                                interfaceStatsCollectionFailureReason:
                                    description: It is the flow analysis's interfaceStatsCollectionFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<interfacestatscollectionfailurereason>'
                                name:
                                    description: It is the flow analysis's name.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<name>'
                                pathOverlayInfo:
                                    description: It is the flow analysis's pathOverlayInfo.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        controlPlane:
                                            description: It is the flow analysis's controlPlane.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<controlplane>'
                                        dataPacketEncapsulation:
                                            description: It is the flow analysis's dataPacketEncapsulation.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<datapacketencapsulation>'
                                        destIp:
                                            description: It is the flow analysis's destIp.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<destip>'
                                        destPort:
                                            description: It is the flow analysis's destPort.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<destport>'
                                        protocol:
                                            description: It is the flow analysis's protocol.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<protocol>'
                                        sourceIp:
                                            description: It is the flow analysis's sourceIp.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<sourceip>'
                                        sourcePort:
                                            description: It is the flow analysis's sourcePort.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<sourceport>'
                                        vxlanInfo:
                                            description: It is the flow analysis's vxlanInfo.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                dscp:
                                                    description: It is the flow analysis's dscp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<dscp>'
                                                vnid:
                                                    description: It is the flow analysis's vnid.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<vnid>'


                                qosStatistics:
                                    description: It is the flow analysis's qosStatistics.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        classMapName:
                                            description: It is the flow analysis's classMapName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<classmapname>'
                                        dropRate:
                                            description: It is the flow analysis's dropRate.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        numBytes:
                                            description: It is the flow analysis's numBytes.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        numPackets:
                                            description: It is the flow analysis's numPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        offeredRate:
                                            description: It is the flow analysis's offeredRate.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueBandwidthbps:
                                            description: It is the flow analysis's queueBandwidthbps.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<queuebandwidthbps>'
                                        queueDepth:
                                            description: It is the flow analysis's queueDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueNoBufferDrops:
                                            description: It is the flow analysis's queueNoBufferDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueTotalDrops:
                                            description: It is the flow analysis's queueTotalDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                qosStatsCollection:
                                    description: It is the flow analysis's qosStatsCollection.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<qosstatscollection>'
                                qosStatsCollectionFailureReason:
                                    description: It is the flow analysis's qosStatsCollectionFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<qosstatscollectionfailurereason>'
                                usedVlan:
                                    description: It is the flow analysis's usedVlan.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<usedvlan>'
                                vrfName:
                                    description: It is the flow analysis's vrfName.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<vrfname>'

                        ingressVirtualInterface:
                            description: It is the flow analysis's ingressVirtualInterface.
                            returned: success,changed,always
                            type: dict
                            contains:
                                aclAnalysis:
                                    description: It is the flow analysis's aclAnalysis.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclName:
                                            description: It is the flow analysis's aclName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<aclname>'
                                        matchingAces:
                                            description: It is the flow analysis's matchingAces.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                ace:
                                                    description: It is the flow analysis's ace.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<ace>'
                                                matchingPorts:
                                                    description: It is the flow analysis's matchingPorts.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ports:
                                                            description: It is the flow analysis's ports.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                destPorts:
                                                                    description: It is the flow analysis's destPorts.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                sourcePorts:
                                                                    description: It is the flow analysis's sourcePorts.
                                                                    returned: success,changed,always
                                                                    type: list

                                                        protocol:
                                                            description: It is the flow analysis's protocol.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<protocol>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        result:
                                            description: It is the flow analysis's result.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<result>'

                                id:
                                    description: It is the flow analysis's id.
                                    returned: success,changed,always
                                    type: str
                                    sample: '478012'
                                interfaceStatistics:
                                    description: It is the flow analysis's interfaceStatistics.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        adminStatus:
                                            description: It is the flow analysis's adminStatus.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<adminstatus>'
                                        inputPackets:
                                            description: It is the flow analysis's inputPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueCount:
                                            description: It is the flow analysis's inputQueueCount.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueDrops:
                                            description: It is the flow analysis's inputQueueDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueFlushes:
                                            description: It is the flow analysis's inputQueueFlushes.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputQueueMaxDepth:
                                            description: It is the flow analysis's inputQueueMaxDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        inputRatebps:
                                            description: It is the flow analysis's inputRatebps.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        operationalStatus:
                                            description: It is the flow analysis's operationalStatus.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<operationalstatus>'
                                        outputDrop:
                                            description: It is the flow analysis's outputDrop.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputPackets:
                                            description: It is the flow analysis's outputPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputQueueCount:
                                            description: It is the flow analysis's outputQueueCount.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputQueueDepth:
                                            description: It is the flow analysis's outputQueueDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        outputRatebps:
                                            description: It is the flow analysis's outputRatebps.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                interfaceStatsCollection:
                                    description: It is the flow analysis's interfaceStatsCollection.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<interfacestatscollection>'
                                interfaceStatsCollectionFailureReason:
                                    description: It is the flow analysis's interfaceStatsCollectionFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<interfacestatscollectionfailurereason>'
                                name:
                                    description: It is the flow analysis's name.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<name>'
                                pathOverlayInfo:
                                    description: It is the flow analysis's pathOverlayInfo.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        controlPlane:
                                            description: It is the flow analysis's controlPlane.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<controlplane>'
                                        dataPacketEncapsulation:
                                            description: It is the flow analysis's dataPacketEncapsulation.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<datapacketencapsulation>'
                                        destIp:
                                            description: It is the flow analysis's destIp.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<destip>'
                                        destPort:
                                            description: It is the flow analysis's destPort.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<destport>'
                                        protocol:
                                            description: It is the flow analysis's protocol.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<protocol>'
                                        sourceIp:
                                            description: It is the flow analysis's sourceIp.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<sourceip>'
                                        sourcePort:
                                            description: It is the flow analysis's sourcePort.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<sourceport>'
                                        vxlanInfo:
                                            description: It is the flow analysis's vxlanInfo.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                dscp:
                                                    description: It is the flow analysis's dscp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<dscp>'
                                                vnid:
                                                    description: It is the flow analysis's vnid.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<vnid>'


                                qosStatistics:
                                    description: It is the flow analysis's qosStatistics.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        classMapName:
                                            description: It is the flow analysis's classMapName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<classmapname>'
                                        dropRate:
                                            description: It is the flow analysis's dropRate.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        numBytes:
                                            description: It is the flow analysis's numBytes.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        numPackets:
                                            description: It is the flow analysis's numPackets.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        offeredRate:
                                            description: It is the flow analysis's offeredRate.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueBandwidthbps:
                                            description: It is the flow analysis's queueBandwidthbps.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<queuebandwidthbps>'
                                        queueDepth:
                                            description: It is the flow analysis's queueDepth.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueNoBufferDrops:
                                            description: It is the flow analysis's queueNoBufferDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        queueTotalDrops:
                                            description: It is the flow analysis's queueTotalDrops.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                qosStatsCollection:
                                    description: It is the flow analysis's qosStatsCollection.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<qosstatscollection>'
                                qosStatsCollectionFailureReason:
                                    description: It is the flow analysis's qosStatsCollectionFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<qosstatscollectionfailurereason>'
                                usedVlan:
                                    description: It is the flow analysis's usedVlan.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<usedvlan>'
                                vrfName:
                                    description: It is the flow analysis's vrfName.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<vrfname>'

                        ip:
                            description: It is the flow analysis's ip.
                            returned: success,changed,always
                            type: str
                            sample: '1.1.1.17'
                        linkInformationSource:
                            description: It is the flow analysis's linkInformationSource.
                            returned: success,changed,always
                            type: str
                            sample: '<linkinformationsource>'
                        name:
                            description: It is the flow analysis's name.
                            returned: success,changed,always
                            type: str
                            sample: '<name>'
                        perfMonCollection:
                            description: It is the flow analysis's perfMonCollection.
                            returned: success,changed,always
                            type: str
                            sample: '<perfmoncollection>'
                        perfMonCollectionFailureReason:
                            description: It is the flow analysis's perfMonCollectionFailureReason.
                            returned: success,changed,always
                            type: str
                            sample: '<perfmoncollectionfailurereason>'
                        perfMonStatistics:
                            description: It is the flow analysis's perfMonStatistics.
                            returned: success,changed,always
                            type: list
                            contains:
                                byteRate:
                                    description: It is the flow analysis's byteRate.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                destIpAddress:
                                    description: It is the flow analysis's destIpAddress.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<destipaddress>'
                                destPort:
                                    description: It is the flow analysis's destPort.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<destport>'
                                inputInterface:
                                    description: It is the flow analysis's inputInterface.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<inputinterface>'
                                ipv4DSCP:
                                    description: It is the flow analysis's ipv4DSCP.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<ipv4dscp>'
                                ipv4TTL:
                                    description: It is the flow analysis's ipv4TTL.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                outputInterface:
                                    description: It is the flow analysis's outputInterface.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<outputinterface>'
                                packetBytes:
                                    description: It is the flow analysis's packetBytes.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                packetCount:
                                    description: It is the flow analysis's packetCount.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                packetLoss:
                                    description: It is the flow analysis's packetLoss.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                packetLossPercentage:
                                    description: It is the flow analysis's packetLossPercentage.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                protocol:
                                    description: It is the flow analysis's protocol.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<protocol>'
                                refreshedAt:
                                    description: It is the flow analysis's refreshedAt.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                rtpJitterMax:
                                    description: It is the flow analysis's rtpJitterMax.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                rtpJitterMean:
                                    description: It is the flow analysis's rtpJitterMean.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                rtpJitterMin:
                                    description: It is the flow analysis's rtpJitterMin.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                sourceIpAddress:
                                    description: It is the flow analysis's sourceIpAddress.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<sourceipaddress>'
                                sourcePort:
                                    description: It is the flow analysis's sourcePort.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<sourceport>'

                        role:
                            description: It is the flow analysis's role.
                            returned: success,changed,always
                            type: str
                            sample: '<role>'
                        ssid:
                            description: It is the flow analysis's ssid.
                            returned: success,changed,always
                            type: str
                            sample: '<ssid>'
                        tunnels:
                            description: It is the flow analysis's tunnels.
                            returned: success,changed,always
                            type: list
                        type:
                            description: It is the flow analysis's type.
                            returned: success,changed,always
                            type: str
                            sample: '<type>'
                        wlanId:
                            description: It is the flow analysis's wlanId.
                            returned: success,changed,always
                            type: str
                            sample: '<wlanid>'

                networkElementsInfo:
                    description: It is the flow analysis's networkElementsInfo.
                    returned: success,changed,always
                    type: list
                    contains:
                        accuracyList:
                            description: It is the flow analysis's accuracyList.
                            returned: success,changed,always
                            type: list
                            contains:
                                percent:
                                    description: It is the flow analysis's percent.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                reason:
                                    description: It is the flow analysis's reason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<reason>'

                        detailedStatus:
                            description: It is the flow analysis's detailedStatus.
                            returned: success,changed,always
                            type: dict
                            contains:
                                aclTraceCalculation:
                                    description: It is the flow analysis's aclTraceCalculation.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<acltracecalculation>'
                                aclTraceCalculationFailureReason:
                                    description: It is the flow analysis's aclTraceCalculationFailureReason.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<acltracecalculationfailurereason>'

                        deviceStatistics:
                            description: It is the flow analysis's deviceStatistics.
                            returned: success,changed,always
                            type: dict
                            contains:
                                cpuStatistics:
                                    description: It is the flow analysis's cpuStatistics.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        fiveMinUsageInPercentage:
                                            description: It is the flow analysis's fiveMinUsageInPercentage.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        fiveSecsUsageInPercentage:
                                            description: It is the flow analysis's fiveSecsUsageInPercentage.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        oneMinUsageInPercentage:
                                            description: It is the flow analysis's oneMinUsageInPercentage.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0

                                memoryStatistics:
                                    description: It is the flow analysis's memoryStatistics.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        memoryUsage:
                                            description: It is the flow analysis's memoryUsage.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        refreshedAt:
                                            description: It is the flow analysis's refreshedAt.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0
                                        totalMemory:
                                            description: It is the flow analysis's totalMemory.
                                            returned: success,changed,always
                                            type: int
                                            sample: 0


                        deviceStatsCollection:
                            description: It is the flow analysis's deviceStatsCollection.
                            returned: success,changed,always
                            type: str
                            sample: '<devicestatscollection>'
                        deviceStatsCollectionFailureReason:
                            description: It is the flow analysis's deviceStatsCollectionFailureReason.
                            returned: success,changed,always
                            type: str
                            sample: '<devicestatscollectionfailurereason>'
                        egressInterface:
                            description: It is the flow analysis's egressInterface.
                            returned: success,changed,always
                            type: dict
                            contains:
                                physicalInterface:
                                    description: It is the flow analysis's physicalInterface.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclAnalysis:
                                            description: It is the flow analysis's aclAnalysis.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                aclName:
                                                    description: It is the flow analysis's aclName.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<aclname>'
                                                matchingAces:
                                                    description: It is the flow analysis's matchingAces.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ace:
                                                            description: It is the flow analysis's ace.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<ace>'
                                                        matchingPorts:
                                                            description: It is the flow analysis's matchingPorts.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                ports:
                                                                    description: It is the flow analysis's ports.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                    contains:
                                                                        destPorts:
                                                                            description: It is the flow analysis's destPorts.
                                                                            returned: success,changed,always
                                                                            type: list
                                                                        sourcePorts:
                                                                            description: It is the flow analysis's sourcePorts.
                                                                            returned: success,changed,always
                                                                            type: list

                                                                protocol:
                                                                    description: It is the flow analysis's protocol.
                                                                    returned: success,changed,always
                                                                    type: str
                                                                    sample: '<protocol>'

                                                        result:
                                                            description: It is the flow analysis's result.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<result>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        id:
                                            description: It is the flow analysis's id.
                                            returned: success,changed,always
                                            type: str
                                            sample: '478012'
                                        interfaceStatistics:
                                            description: It is the flow analysis's interfaceStatistics.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                adminStatus:
                                                    description: It is the flow analysis's adminStatus.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<adminstatus>'
                                                inputPackets:
                                                    description: It is the flow analysis's inputPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueCount:
                                                    description: It is the flow analysis's inputQueueCount.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueDrops:
                                                    description: It is the flow analysis's inputQueueDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueFlushes:
                                                    description: It is the flow analysis's inputQueueFlushes.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueMaxDepth:
                                                    description: It is the flow analysis's inputQueueMaxDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputRatebps:
                                                    description: It is the flow analysis's inputRatebps.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                operationalStatus:
                                                    description: It is the flow analysis's operationalStatus.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<operationalstatus>'
                                                outputDrop:
                                                    description: It is the flow analysis's outputDrop.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputPackets:
                                                    description: It is the flow analysis's outputPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputQueueCount:
                                                    description: It is the flow analysis's outputQueueCount.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputQueueDepth:
                                                    description: It is the flow analysis's outputQueueDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputRatebps:
                                                    description: It is the flow analysis's outputRatebps.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                refreshedAt:
                                                    description: It is the flow analysis's refreshedAt.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0

                                        interfaceStatsCollection:
                                            description: It is the flow analysis's interfaceStatsCollection.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<interfacestatscollection>'
                                        interfaceStatsCollectionFailureReason:
                                            description: It is the flow analysis's interfaceStatsCollectionFailureReason.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<interfacestatscollectionfailurereason>'
                                        name:
                                            description: It is the flow analysis's name.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<name>'
                                        pathOverlayInfo:
                                            description: It is the flow analysis's pathOverlayInfo.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                controlPlane:
                                                    description: It is the flow analysis's controlPlane.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<controlplane>'
                                                dataPacketEncapsulation:
                                                    description: It is the flow analysis's dataPacketEncapsulation.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<datapacketencapsulation>'
                                                destIp:
                                                    description: It is the flow analysis's destIp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<destip>'
                                                destPort:
                                                    description: It is the flow analysis's destPort.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<destport>'
                                                protocol:
                                                    description: It is the flow analysis's protocol.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<protocol>'
                                                sourceIp:
                                                    description: It is the flow analysis's sourceIp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<sourceip>'
                                                sourcePort:
                                                    description: It is the flow analysis's sourcePort.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<sourceport>'
                                                vxlanInfo:
                                                    description: It is the flow analysis's vxlanInfo.
                                                    returned: success,changed,always
                                                    type: dict
                                                    contains:
                                                        dscp:
                                                            description: It is the flow analysis's dscp.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<dscp>'
                                                        vnid:
                                                            description: It is the flow analysis's vnid.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<vnid>'


                                        qosStatistics:
                                            description: It is the flow analysis's qosStatistics.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                classMapName:
                                                    description: It is the flow analysis's classMapName.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<classmapname>'
                                                dropRate:
                                                    description: It is the flow analysis's dropRate.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                numBytes:
                                                    description: It is the flow analysis's numBytes.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                numPackets:
                                                    description: It is the flow analysis's numPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                offeredRate:
                                                    description: It is the flow analysis's offeredRate.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueBandwidthbps:
                                                    description: It is the flow analysis's queueBandwidthbps.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<queuebandwidthbps>'
                                                queueDepth:
                                                    description: It is the flow analysis's queueDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueNoBufferDrops:
                                                    description: It is the flow analysis's queueNoBufferDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueTotalDrops:
                                                    description: It is the flow analysis's queueTotalDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                refreshedAt:
                                                    description: It is the flow analysis's refreshedAt.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0

                                        qosStatsCollection:
                                            description: It is the flow analysis's qosStatsCollection.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<qosstatscollection>'
                                        qosStatsCollectionFailureReason:
                                            description: It is the flow analysis's qosStatsCollectionFailureReason.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<qosstatscollectionfailurereason>'
                                        usedVlan:
                                            description: It is the flow analysis's usedVlan.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<usedvlan>'
                                        vrfName:
                                            description: It is the flow analysis's vrfName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<vrfname>'

                                virtualInterface:
                                    description: It is the flow analysis's virtualInterface.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        aclAnalysis:
                                            description: It is the flow analysis's aclAnalysis.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                aclName:
                                                    description: It is the flow analysis's aclName.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<aclname>'
                                                matchingAces:
                                                    description: It is the flow analysis's matchingAces.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ace:
                                                            description: It is the flow analysis's ace.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<ace>'
                                                        matchingPorts:
                                                            description: It is the flow analysis's matchingPorts.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                ports:
                                                                    description: It is the flow analysis's ports.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                    contains:
                                                                        destPorts:
                                                                            description: It is the flow analysis's destPorts.
                                                                            returned: success,changed,always
                                                                            type: list
                                                                        sourcePorts:
                                                                            description: It is the flow analysis's sourcePorts.
                                                                            returned: success,changed,always
                                                                            type: list

                                                                protocol:
                                                                    description: It is the flow analysis's protocol.
                                                                    returned: success,changed,always
                                                                    type: str
                                                                    sample: '<protocol>'

                                                        result:
                                                            description: It is the flow analysis's result.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<result>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        id:
                                            description: It is the flow analysis's id.
                                            returned: success,changed,always
                                            type: str
                                            sample: '478012'
                                        interfaceStatistics:
                                            description: It is the flow analysis's interfaceStatistics.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                adminStatus:
                                                    description: It is the flow analysis's adminStatus.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<adminstatus>'
                                                inputPackets:
                                                    description: It is the flow analysis's inputPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueCount:
                                                    description: It is the flow analysis's inputQueueCount.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueDrops:
                                                    description: It is the flow analysis's inputQueueDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueFlushes:
                                                    description: It is the flow analysis's inputQueueFlushes.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueMaxDepth:
                                                    description: It is the flow analysis's inputQueueMaxDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputRatebps:
                                                    description: It is the flow analysis's inputRatebps.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                operationalStatus:
                                                    description: It is the flow analysis's operationalStatus.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<operationalstatus>'
                                                outputDrop:
                                                    description: It is the flow analysis's outputDrop.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputPackets:
                                                    description: It is the flow analysis's outputPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputQueueCount:
                                                    description: It is the flow analysis's outputQueueCount.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputQueueDepth:
                                                    description: It is the flow analysis's outputQueueDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputRatebps:
                                                    description: It is the flow analysis's outputRatebps.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                refreshedAt:
                                                    description: It is the flow analysis's refreshedAt.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0

                                        interfaceStatsCollection:
                                            description: It is the flow analysis's interfaceStatsCollection.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<interfacestatscollection>'
                                        interfaceStatsCollectionFailureReason:
                                            description: It is the flow analysis's interfaceStatsCollectionFailureReason.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<interfacestatscollectionfailurereason>'
                                        name:
                                            description: It is the flow analysis's name.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<name>'
                                        pathOverlayInfo:
                                            description: It is the flow analysis's pathOverlayInfo.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                controlPlane:
                                                    description: It is the flow analysis's controlPlane.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<controlplane>'
                                                dataPacketEncapsulation:
                                                    description: It is the flow analysis's dataPacketEncapsulation.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<datapacketencapsulation>'
                                                destIp:
                                                    description: It is the flow analysis's destIp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<destip>'
                                                destPort:
                                                    description: It is the flow analysis's destPort.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<destport>'
                                                protocol:
                                                    description: It is the flow analysis's protocol.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<protocol>'
                                                sourceIp:
                                                    description: It is the flow analysis's sourceIp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<sourceip>'
                                                sourcePort:
                                                    description: It is the flow analysis's sourcePort.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<sourceport>'
                                                vxlanInfo:
                                                    description: It is the flow analysis's vxlanInfo.
                                                    returned: success,changed,always
                                                    type: dict
                                                    contains:
                                                        dscp:
                                                            description: It is the flow analysis's dscp.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<dscp>'
                                                        vnid:
                                                            description: It is the flow analysis's vnid.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<vnid>'


                                        qosStatistics:
                                            description: It is the flow analysis's qosStatistics.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                classMapName:
                                                    description: It is the flow analysis's classMapName.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<classmapname>'
                                                dropRate:
                                                    description: It is the flow analysis's dropRate.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                numBytes:
                                                    description: It is the flow analysis's numBytes.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                numPackets:
                                                    description: It is the flow analysis's numPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                offeredRate:
                                                    description: It is the flow analysis's offeredRate.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueBandwidthbps:
                                                    description: It is the flow analysis's queueBandwidthbps.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<queuebandwidthbps>'
                                                queueDepth:
                                                    description: It is the flow analysis's queueDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueNoBufferDrops:
                                                    description: It is the flow analysis's queueNoBufferDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueTotalDrops:
                                                    description: It is the flow analysis's queueTotalDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                refreshedAt:
                                                    description: It is the flow analysis's refreshedAt.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0

                                        qosStatsCollection:
                                            description: It is the flow analysis's qosStatsCollection.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<qosstatscollection>'
                                        qosStatsCollectionFailureReason:
                                            description: It is the flow analysis's qosStatsCollectionFailureReason.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<qosstatscollectionfailurereason>'
                                        usedVlan:
                                            description: It is the flow analysis's usedVlan.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<usedvlan>'
                                        vrfName:
                                            description: It is the flow analysis's vrfName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<vrfname>'


                        flexConnect:
                            description: It is the flow analysis's flexConnect.
                            returned: success,changed,always
                            type: dict
                            contains:
                                authentication:
                                    description: It is the flow analysis's authentication.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<authentication>'
                                dataSwitching:
                                    description: It is the flow analysis's dataSwitching.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<dataswitching>'
                                egressAclAnalysis:
                                    description: It is the flow analysis's egressAclAnalysis.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclName:
                                            description: It is the flow analysis's aclName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<aclname>'
                                        matchingAces:
                                            description: It is the flow analysis's matchingAces.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                ace:
                                                    description: It is the flow analysis's ace.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<ace>'
                                                matchingPorts:
                                                    description: It is the flow analysis's matchingPorts.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ports:
                                                            description: It is the flow analysis's ports.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                destPorts:
                                                                    description: It is the flow analysis's destPorts.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                sourcePorts:
                                                                    description: It is the flow analysis's sourcePorts.
                                                                    returned: success,changed,always
                                                                    type: list

                                                        protocol:
                                                            description: It is the flow analysis's protocol.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<protocol>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        result:
                                            description: It is the flow analysis's result.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<result>'

                                ingressAclAnalysis:
                                    description: It is the flow analysis's ingressAclAnalysis.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclName:
                                            description: It is the flow analysis's aclName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<aclname>'
                                        matchingAces:
                                            description: It is the flow analysis's matchingAces.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                ace:
                                                    description: It is the flow analysis's ace.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<ace>'
                                                matchingPorts:
                                                    description: It is the flow analysis's matchingPorts.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ports:
                                                            description: It is the flow analysis's ports.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                destPorts:
                                                                    description: It is the flow analysis's destPorts.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                sourcePorts:
                                                                    description: It is the flow analysis's sourcePorts.
                                                                    returned: success,changed,always
                                                                    type: list

                                                        protocol:
                                                            description: It is the flow analysis's protocol.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<protocol>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        result:
                                            description: It is the flow analysis's result.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<result>'

                                wirelessLanControllerId:
                                    description: It is the flow analysis's wirelessLanControllerId.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<wirelesslancontrollerid>'
                                wirelessLanControllerName:
                                    description: It is the flow analysis's wirelessLanControllerName.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<wirelesslancontrollername>'

                        id:
                            description: It is the flow analysis's id.
                            returned: success,changed,always
                            type: str
                            sample: '478012'
                        ingressInterface:
                            description: It is the flow analysis's ingressInterface.
                            returned: success,changed,always
                            type: dict
                            contains:
                                physicalInterface:
                                    description: It is the flow analysis's physicalInterface.
                                    returned: success,changed,always
                                    type: dict
                                    contains:
                                        aclAnalysis:
                                            description: It is the flow analysis's aclAnalysis.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                aclName:
                                                    description: It is the flow analysis's aclName.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<aclname>'
                                                matchingAces:
                                                    description: It is the flow analysis's matchingAces.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ace:
                                                            description: It is the flow analysis's ace.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<ace>'
                                                        matchingPorts:
                                                            description: It is the flow analysis's matchingPorts.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                ports:
                                                                    description: It is the flow analysis's ports.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                    contains:
                                                                        destPorts:
                                                                            description: It is the flow analysis's destPorts.
                                                                            returned: success,changed,always
                                                                            type: list
                                                                        sourcePorts:
                                                                            description: It is the flow analysis's sourcePorts.
                                                                            returned: success,changed,always
                                                                            type: list

                                                                protocol:
                                                                    description: It is the flow analysis's protocol.
                                                                    returned: success,changed,always
                                                                    type: str
                                                                    sample: '<protocol>'

                                                        result:
                                                            description: It is the flow analysis's result.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<result>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        id:
                                            description: It is the flow analysis's id.
                                            returned: success,changed,always
                                            type: str
                                            sample: '478012'
                                        interfaceStatistics:
                                            description: It is the flow analysis's interfaceStatistics.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                adminStatus:
                                                    description: It is the flow analysis's adminStatus.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<adminstatus>'
                                                inputPackets:
                                                    description: It is the flow analysis's inputPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueCount:
                                                    description: It is the flow analysis's inputQueueCount.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueDrops:
                                                    description: It is the flow analysis's inputQueueDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueFlushes:
                                                    description: It is the flow analysis's inputQueueFlushes.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueMaxDepth:
                                                    description: It is the flow analysis's inputQueueMaxDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputRatebps:
                                                    description: It is the flow analysis's inputRatebps.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                operationalStatus:
                                                    description: It is the flow analysis's operationalStatus.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<operationalstatus>'
                                                outputDrop:
                                                    description: It is the flow analysis's outputDrop.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputPackets:
                                                    description: It is the flow analysis's outputPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputQueueCount:
                                                    description: It is the flow analysis's outputQueueCount.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputQueueDepth:
                                                    description: It is the flow analysis's outputQueueDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputRatebps:
                                                    description: It is the flow analysis's outputRatebps.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                refreshedAt:
                                                    description: It is the flow analysis's refreshedAt.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0

                                        interfaceStatsCollection:
                                            description: It is the flow analysis's interfaceStatsCollection.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<interfacestatscollection>'
                                        interfaceStatsCollectionFailureReason:
                                            description: It is the flow analysis's interfaceStatsCollectionFailureReason.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<interfacestatscollectionfailurereason>'
                                        name:
                                            description: It is the flow analysis's name.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<name>'
                                        pathOverlayInfo:
                                            description: It is the flow analysis's pathOverlayInfo.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                controlPlane:
                                                    description: It is the flow analysis's controlPlane.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<controlplane>'
                                                dataPacketEncapsulation:
                                                    description: It is the flow analysis's dataPacketEncapsulation.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<datapacketencapsulation>'
                                                destIp:
                                                    description: It is the flow analysis's destIp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<destip>'
                                                destPort:
                                                    description: It is the flow analysis's destPort.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<destport>'
                                                protocol:
                                                    description: It is the flow analysis's protocol.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<protocol>'
                                                sourceIp:
                                                    description: It is the flow analysis's sourceIp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<sourceip>'
                                                sourcePort:
                                                    description: It is the flow analysis's sourcePort.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<sourceport>'
                                                vxlanInfo:
                                                    description: It is the flow analysis's vxlanInfo.
                                                    returned: success,changed,always
                                                    type: dict
                                                    contains:
                                                        dscp:
                                                            description: It is the flow analysis's dscp.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<dscp>'
                                                        vnid:
                                                            description: It is the flow analysis's vnid.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<vnid>'


                                        qosStatistics:
                                            description: It is the flow analysis's qosStatistics.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                classMapName:
                                                    description: It is the flow analysis's classMapName.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<classmapname>'
                                                dropRate:
                                                    description: It is the flow analysis's dropRate.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                numBytes:
                                                    description: It is the flow analysis's numBytes.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                numPackets:
                                                    description: It is the flow analysis's numPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                offeredRate:
                                                    description: It is the flow analysis's offeredRate.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueBandwidthbps:
                                                    description: It is the flow analysis's queueBandwidthbps.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<queuebandwidthbps>'
                                                queueDepth:
                                                    description: It is the flow analysis's queueDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueNoBufferDrops:
                                                    description: It is the flow analysis's queueNoBufferDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueTotalDrops:
                                                    description: It is the flow analysis's queueTotalDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                refreshedAt:
                                                    description: It is the flow analysis's refreshedAt.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0

                                        qosStatsCollection:
                                            description: It is the flow analysis's qosStatsCollection.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<qosstatscollection>'
                                        qosStatsCollectionFailureReason:
                                            description: It is the flow analysis's qosStatsCollectionFailureReason.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<qosstatscollectionfailurereason>'
                                        usedVlan:
                                            description: It is the flow analysis's usedVlan.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<usedvlan>'
                                        vrfName:
                                            description: It is the flow analysis's vrfName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<vrfname>'

                                virtualInterface:
                                    description: It is the flow analysis's virtualInterface.
                                    returned: success,changed,always
                                    type: list
                                    contains:
                                        aclAnalysis:
                                            description: It is the flow analysis's aclAnalysis.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                aclName:
                                                    description: It is the flow analysis's aclName.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<aclname>'
                                                matchingAces:
                                                    description: It is the flow analysis's matchingAces.
                                                    returned: success,changed,always
                                                    type: list
                                                    contains:
                                                        ace:
                                                            description: It is the flow analysis's ace.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<ace>'
                                                        matchingPorts:
                                                            description: It is the flow analysis's matchingPorts.
                                                            returned: success,changed,always
                                                            type: list
                                                            contains:
                                                                ports:
                                                                    description: It is the flow analysis's ports.
                                                                    returned: success,changed,always
                                                                    type: list
                                                                    contains:
                                                                        destPorts:
                                                                            description: It is the flow analysis's destPorts.
                                                                            returned: success,changed,always
                                                                            type: list
                                                                        sourcePorts:
                                                                            description: It is the flow analysis's sourcePorts.
                                                                            returned: success,changed,always
                                                                            type: list

                                                                protocol:
                                                                    description: It is the flow analysis's protocol.
                                                                    returned: success,changed,always
                                                                    type: str
                                                                    sample: '<protocol>'

                                                        result:
                                                            description: It is the flow analysis's result.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<result>'

                                                result:
                                                    description: It is the flow analysis's result.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<result>'

                                        id:
                                            description: It is the flow analysis's id.
                                            returned: success,changed,always
                                            type: str
                                            sample: '478012'
                                        interfaceStatistics:
                                            description: It is the flow analysis's interfaceStatistics.
                                            returned: success,changed,always
                                            type: dict
                                            contains:
                                                adminStatus:
                                                    description: It is the flow analysis's adminStatus.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<adminstatus>'
                                                inputPackets:
                                                    description: It is the flow analysis's inputPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueCount:
                                                    description: It is the flow analysis's inputQueueCount.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueDrops:
                                                    description: It is the flow analysis's inputQueueDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueFlushes:
                                                    description: It is the flow analysis's inputQueueFlushes.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputQueueMaxDepth:
                                                    description: It is the flow analysis's inputQueueMaxDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                inputRatebps:
                                                    description: It is the flow analysis's inputRatebps.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                operationalStatus:
                                                    description: It is the flow analysis's operationalStatus.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<operationalstatus>'
                                                outputDrop:
                                                    description: It is the flow analysis's outputDrop.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputPackets:
                                                    description: It is the flow analysis's outputPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputQueueCount:
                                                    description: It is the flow analysis's outputQueueCount.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputQueueDepth:
                                                    description: It is the flow analysis's outputQueueDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                outputRatebps:
                                                    description: It is the flow analysis's outputRatebps.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                refreshedAt:
                                                    description: It is the flow analysis's refreshedAt.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0

                                        interfaceStatsCollection:
                                            description: It is the flow analysis's interfaceStatsCollection.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<interfacestatscollection>'
                                        interfaceStatsCollectionFailureReason:
                                            description: It is the flow analysis's interfaceStatsCollectionFailureReason.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<interfacestatscollectionfailurereason>'
                                        name:
                                            description: It is the flow analysis's name.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<name>'
                                        pathOverlayInfo:
                                            description: It is the flow analysis's pathOverlayInfo.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                controlPlane:
                                                    description: It is the flow analysis's controlPlane.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<controlplane>'
                                                dataPacketEncapsulation:
                                                    description: It is the flow analysis's dataPacketEncapsulation.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<datapacketencapsulation>'
                                                destIp:
                                                    description: It is the flow analysis's destIp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<destip>'
                                                destPort:
                                                    description: It is the flow analysis's destPort.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<destport>'
                                                protocol:
                                                    description: It is the flow analysis's protocol.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<protocol>'
                                                sourceIp:
                                                    description: It is the flow analysis's sourceIp.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<sourceip>'
                                                sourcePort:
                                                    description: It is the flow analysis's sourcePort.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<sourceport>'
                                                vxlanInfo:
                                                    description: It is the flow analysis's vxlanInfo.
                                                    returned: success,changed,always
                                                    type: dict
                                                    contains:
                                                        dscp:
                                                            description: It is the flow analysis's dscp.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<dscp>'
                                                        vnid:
                                                            description: It is the flow analysis's vnid.
                                                            returned: success,changed,always
                                                            type: str
                                                            sample: '<vnid>'


                                        qosStatistics:
                                            description: It is the flow analysis's qosStatistics.
                                            returned: success,changed,always
                                            type: list
                                            contains:
                                                classMapName:
                                                    description: It is the flow analysis's classMapName.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<classmapname>'
                                                dropRate:
                                                    description: It is the flow analysis's dropRate.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                numBytes:
                                                    description: It is the flow analysis's numBytes.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                numPackets:
                                                    description: It is the flow analysis's numPackets.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                offeredRate:
                                                    description: It is the flow analysis's offeredRate.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueBandwidthbps:
                                                    description: It is the flow analysis's queueBandwidthbps.
                                                    returned: success,changed,always
                                                    type: str
                                                    sample: '<queuebandwidthbps>'
                                                queueDepth:
                                                    description: It is the flow analysis's queueDepth.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueNoBufferDrops:
                                                    description: It is the flow analysis's queueNoBufferDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                queueTotalDrops:
                                                    description: It is the flow analysis's queueTotalDrops.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0
                                                refreshedAt:
                                                    description: It is the flow analysis's refreshedAt.
                                                    returned: success,changed,always
                                                    type: int
                                                    sample: 0

                                        qosStatsCollection:
                                            description: It is the flow analysis's qosStatsCollection.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<qosstatscollection>'
                                        qosStatsCollectionFailureReason:
                                            description: It is the flow analysis's qosStatsCollectionFailureReason.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<qosstatscollectionfailurereason>'
                                        usedVlan:
                                            description: It is the flow analysis's usedVlan.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<usedvlan>'
                                        vrfName:
                                            description: It is the flow analysis's vrfName.
                                            returned: success,changed,always
                                            type: str
                                            sample: '<vrfname>'


                        ip:
                            description: It is the flow analysis's ip.
                            returned: success,changed,always
                            type: str
                            sample: '1.1.1.17'
                        linkInformationSource:
                            description: It is the flow analysis's linkInformationSource.
                            returned: success,changed,always
                            type: str
                            sample: '<linkinformationsource>'
                        name:
                            description: It is the flow analysis's name.
                            returned: success,changed,always
                            type: str
                            sample: '<name>'
                        perfMonCollection:
                            description: It is the flow analysis's perfMonCollection.
                            returned: success,changed,always
                            type: str
                            sample: '<perfmoncollection>'
                        perfMonCollectionFailureReason:
                            description: It is the flow analysis's perfMonCollectionFailureReason.
                            returned: success,changed,always
                            type: str
                            sample: '<perfmoncollectionfailurereason>'
                        perfMonitorStatistics:
                            description: It is the flow analysis's perfMonitorStatistics.
                            returned: success,changed,always
                            type: list
                            contains:
                                byteRate:
                                    description: It is the flow analysis's byteRate.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                destIpAddress:
                                    description: It is the flow analysis's destIpAddress.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<destipaddress>'
                                destPort:
                                    description: It is the flow analysis's destPort.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<destport>'
                                inputInterface:
                                    description: It is the flow analysis's inputInterface.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<inputinterface>'
                                ipv4DSCP:
                                    description: It is the flow analysis's ipv4DSCP.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<ipv4dscp>'
                                ipv4TTL:
                                    description: It is the flow analysis's ipv4TTL.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                outputInterface:
                                    description: It is the flow analysis's outputInterface.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<outputinterface>'
                                packetBytes:
                                    description: It is the flow analysis's packetBytes.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                packetCount:
                                    description: It is the flow analysis's packetCount.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                packetLoss:
                                    description: It is the flow analysis's packetLoss.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                packetLossPercentage:
                                    description: It is the flow analysis's packetLossPercentage.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                protocol:
                                    description: It is the flow analysis's protocol.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<protocol>'
                                refreshedAt:
                                    description: It is the flow analysis's refreshedAt.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                rtpJitterMax:
                                    description: It is the flow analysis's rtpJitterMax.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                rtpJitterMean:
                                    description: It is the flow analysis's rtpJitterMean.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                rtpJitterMin:
                                    description: It is the flow analysis's rtpJitterMin.
                                    returned: success,changed,always
                                    type: int
                                    sample: 0
                                sourceIpAddress:
                                    description: It is the flow analysis's sourceIpAddress.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<sourceipaddress>'
                                sourcePort:
                                    description: It is the flow analysis's sourcePort.
                                    returned: success,changed,always
                                    type: str
                                    sample: '<sourceport>'

                        role:
                            description: It is the flow analysis's role.
                            returned: success,changed,always
                            type: str
                            sample: '<role>'
                        ssid:
                            description: It is the flow analysis's ssid.
                            returned: success,changed,always
                            type: str
                            sample: '<ssid>'
                        tunnels:
                            description: It is the flow analysis's tunnels.
                            returned: success,changed,always
                            type: list
                        type:
                            description: It is the flow analysis's type.
                            returned: success,changed,always
                            type: str
                            sample: '<type>'
                        wlanId:
                            description: It is the flow analysis's wlanId.
                            returned: success,changed,always
                            type: str
                            sample: '<wlanid>'

                properties:
                    description: It is the flow analysis's properties.
                    returned: success,changed,always
                    type: list
                request:
                    description: It is the flow analysis's request.
                    returned: success,changed,always
                    type: dict
                    contains:
                        controlPath:
                            description: It is the flow analysis's controlPath.
                            returned: success,changed,always
                            type: bool
                            sample: false
                        createTime:
                            description: It is the flow analysis's createTime.
                            returned: success,changed,always
                            type: int
                            sample: 0
                        destIP:
                            description: It is the flow analysis's destIP.
                            returned: success,changed,always
                            type: str
                            sample: '<destip>'
                        destPort:
                            description: It is the flow analysis's destPort.
                            returned: success,changed,always
                            type: str
                            sample: '<destport>'
                        failureReason:
                            description: It is the flow analysis's failureReason.
                            returned: success,changed,always
                            type: str
                            sample: '<failurereason>'
                        id:
                            description: It is the flow analysis's id.
                            returned: success,changed,always
                            type: str
                            sample: '478012'
                        inclusions:
                            description: It is the flow analysis's inclusions.
                            returned: success,changed,always
                            type: list
                        lastUpdateTime:
                            description: It is the flow analysis's lastUpdateTime.
                            returned: success,changed,always
                            type: int
                            sample: 0
                        periodicRefresh:
                            description: It is the flow analysis's periodicRefresh.
                            returned: success,changed,always
                            type: bool
                            sample: false
                        protocol:
                            description: It is the flow analysis's protocol.
                            returned: success,changed,always
                            type: str
                            sample: '<protocol>'
                        sourceIP:
                            description: It is the flow analysis's sourceIP.
                            returned: success,changed,always
                            type: str
                            sample: '<sourceip>'
                        sourcePort:
                            description: It is the flow analysis's sourcePort.
                            returned: success,changed,always
                            type: str
                            sample: '<sourceport>'
                        status:
                            description: It is the flow analysis's status.
                            returned: success,changed,always
                            type: str
                            sample: '<status>'


        version:
            description: Version, property of the response body.
            returned: success,changed,always
            type: str
            sample: '1.0'

data_3:
    description: Deletes a flow analysis request by its id.
    returned: success,changed,always
    type: dict
    contains:
        response:
            description: Response, property of the response body.
            returned: success,changed,always
            type: dict
            contains:
                taskId:
                    description: It is the flow analysis's taskId.
                    returned: success,changed,always
                    type: dict
                url:
                    description: It is the flow analysis's url.
                    returned: success,changed,always
                    type: str
                    sample: '<url>'

        version:
            description: Version, property of the response body.
            returned: success,changed,always
            type: str
            sample: '1.0'

"""
