package org.onosproject.provider.of.flow.impl;

import org.onlab.packet.Ip4Address;
import org.onosproject.net.PortNumber;
import org.onosproject.net.driver.DriverService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions.OutputInstruction;
import org.onosproject.net.flow.instructions.Instructions.SetQueueInstruction;
import org.onosproject.net.flow.instructions.L2ModificationInstruction;
import org.onosproject.net.flow.instructions.L2ModificationInstruction.ModEtherInstruction;
import org.onosproject.net.flow.instructions.L2ModificationInstruction.ModVlanIdInstruction;
import org.onosproject.net.flow.instructions.L2ModificationInstruction.ModVlanPcpInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction.ModIPInstruction;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModFlags;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionEnqueue;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanPcp;
import org.projectfloodlight.openflow.types.VlanVid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onosproject.provider.of.flow.mof.impl.MofFlowDelImpl;
import org.onosproject.provider.of.flow.mof.impl.MofFlowDelSpecImpl;

import org.onosproject.net.DeviceId;
import org.onosproject.net.OchSignal;
import org.onosproject.net.OduSignalId;
import org.onosproject.net.driver.DefaultDriverData;
import org.onosproject.net.driver.DefaultDriverHandler;
import org.onosproject.net.driver.Driver;
import org.onosproject.net.driver.DriverService;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.provider.of.flow.mof.api.MofFlowMod;
import org.onosproject.provider.of.flow.mof.impl.*;
import org.projectfloodlight.openflow.protocol.*;

public class MofFlowModBuilder {
    private static final Logger log = LoggerFactory.getLogger(MofFlowModBuilder.class);
    private final XidGenerator xidGenerator = XidGenerators.global();
    private final FlowRule flowRule;
    private final TrafficSelector selector;
    private final TrafficTreatment treatment;
    protected final Long xid;
    protected final Optional<DriverService> driverService;
    protected final DeviceId deviceId;

    protected MofFlowModBuilder(FlowRule flowRule, Optional<Long> xid,
                             Optional<DriverService> driverService) {
        this.flowRule = flowRule;
        this.selector = flowRule.selector();
        this.treatment = flowRule.treatment();
        this.xid = xid.orElse(0L);
        this.driverService = driverService;
        this.deviceId = flowRule.deviceId();
    }

    public long nextXid() {
        return xidGenerator.nextXid();
    }

    public MofFlowMod buildMofFlowAdd() {

        long cookie = flowRule().id().value();
        //log.info("cookie = " + cookie);
        TableId tableId = TableId.of(flowRule().table().getValue());

        MofFlowMod fm = new MofFlowAddImpl.Builder()
                                        .setXid(xid)
                                        .setTableId(tableId)
                                        .setCookie(U64.of(cookie))
                                        .setBufferId(OFBufferId.NO_BUFFER)
                                        .setTreatment(treatment)
                                        .setSelector(selector)
                                        .setFlags(Collections.singleton(OFFlowModFlags.SEND_FLOW_REM))
                                        .setPriority(flowRule().priority())
                                        .setHardTimeout(flowRule().hardTimeout())
                                        .build();

        return fm;
    }

    public MofFlowAddImpl buildMofFlowMod() {
        return null;
    }

    public MofFlowMod buildMofFlowDel() {
        long cookie = flowRule().id().value();
        TableId tableId = TableId.of(flowRule().table().getValue());

        MofFlowMod fm = new MofFlowDelImpl.Builder()
                                        .setXid(xid)
                                        .setTableId(tableId)
                                        .setCookie(U64.of(cookie))
                                        .setBufferId(OFBufferId.NO_BUFFER)
                                        .setSelector(selector)
                                        .setTreatment(treatment)
                                        .setFlags(Collections.singleton(OFFlowModFlags.SEND_FLOW_REM))
                                        .setHardTimeout(flowRule().hardTimeout())
                                        .build();

        return fm;
    }

    public MofFlowMod buildMofFlowDelSpec() {
        long cookie = flowRule().id().value();
        TableId tableId = TableId.of(flowRule().table().getValue());

        MofFlowMod fm = new MofFlowDelSpecImpl.Builder()
                                        .setXid(xid)
                                        .setTableId(tableId)
                                        .setCookie(U64.of(cookie))
                                        .setBufferId(OFBufferId.NO_BUFFER)
                                        .setSelector(selector)
                                        .setTreatment(treatment)
                                        .setFlags(Collections.singleton(OFFlowModFlags.SEND_FLOW_REM))
                                        .setPriority(flowRule().priority())
                                        .setHardTimeout(flowRule().hardTimeout())
                                        .build();

        return fm;
    }

    public long getXid() {
    return xid;
    }

    public TrafficSelector getSelector() {
    return selector;
    }

    public TrafficTreatment getTreatment() {
    return treatment;
    }

    public FlowRule flowRule() {
        return flowRule;
    }

}