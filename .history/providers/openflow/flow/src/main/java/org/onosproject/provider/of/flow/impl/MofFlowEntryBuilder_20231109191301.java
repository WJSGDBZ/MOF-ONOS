package org.onosproject.provider.of.flow.impl;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.onlab.packet.EthType;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onosproject.core.GroupId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Lambda;
import org.onosproject.net.OduSignalId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.driver.DefaultDriverData;
import org.onosproject.net.driver.DefaultDriverHandler;
import org.onosproject.net.driver.Driver;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.driver.DriverService;
import org.onosproject.net.flow.DefaultFlowEntry;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowEntry.FlowEntryState;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.StatTriggerField;
import org.onosproject.net.flow.StatTriggerFlag;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.ExtensionSelectorType.ExtensionSelectorTypes;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.meter.MeterId;
import org.onosproject.openflow.controller.ExtensionSelectorInterpreter;
import org.onosproject.openflow.controller.ExtensionTreatmentInterpreter;
import org.onosproject.provider.of.flow.impl.NewAdaptiveFlowStatsCollector;
import org.projectfloodlight.openflow.protocol.OFFlowLightweightStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
import org.projectfloodlight.openflow.protocol.OFMatchV3;
import org.projectfloodlight.openflow.protocol.OFObject;
import org.projectfloodlight.openflow.protocol.OFOxsList;
import org.projectfloodlight.openflow.protocol.OFStatTriggerFlags;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionCircuit;
import org.projectfloodlight.openflow.protocol.action.OFActionEnqueue;
import org.projectfloodlight.openflow.protocol.action.OFActionExperimenter;
import org.projectfloodlight.openflow.protocol.action.OFActionGroup;
import org.projectfloodlight.openflow.protocol.action.OFActionMeter;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionPopMpls;
import org.projectfloodlight.openflow.protocol.action.OFActionPushVlan;
import org.projectfloodlight.openflow.protocol.action.OFActionSetDlDst;
import org.projectfloodlight.openflow.protocol.action.OFActionSetDlSrc;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActionSetNwDst;
import org.projectfloodlight.openflow.protocol.action.OFActionSetNwSrc;
import org.projectfloodlight.openflow.protocol.action.OFActionSetQueue;
import org.projectfloodlight.openflow.protocol.action.OFActionSetVlanPcp;
import org.projectfloodlight.openflow.protocol.action.OFActionSetVlanVid;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionGotoTable;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionMeter;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionStatTrigger;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionWriteActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionWriteMetadata;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxm;
import org.projectfloodlight.openflow.protocol.oxm.OFOxmOchSigid;
import org.projectfloodlight.openflow.protocol.oxs.OFOxs;
import org.projectfloodlight.openflow.protocol.ver13.OFFactoryVer13;
import org.projectfloodlight.openflow.types.CircuitSignalID;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpDscp;
import org.projectfloodlight.openflow.types.Masked;
import org.projectfloodlight.openflow.types.OFBooleanValue;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.OduSignalID;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.U32;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.U8;
import org.projectfloodlight.openflow.types.VlanPcp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.onosproject.openflow.controller.mof.api.MofFlowStatsEntry;
import org.onosproject.provider.of.flow.util.FlowStatParser;

import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.onosproject.net.flow.StatTriggerField.*;
import static org.onosproject.net.flow.StatTriggerFlag.ONLY_FIRST;
import static org.onosproject.net.flow.StatTriggerFlag.PERIODIC;
import static org.onosproject.net.flow.criteria.Criteria.*;
import static org.onosproject.net.flow.instructions.Instructions.modL0Lambda;
import static org.onosproject.net.flow.instructions.Instructions.modL1OduSignalId;
import static org.onosproject.provider.of.flow.util.OpenFlowValueMapper.*;


public class MofFlowEntryBuilder {
    private static final Logger log = LoggerFactory.getLogger(MofFlowEntryBuilder.class);

    private final MofFlowStatsEntry stat;
    // private final OFFlowRemoved removed;
    // private final OFFlowMod flowMod;
    // private final OFFlowLightweightStatsEntry lightWeightStat;

    private final TrafficSelector selector;

    // All actions are contained in an OFInstruction. For OF1.0
    // the instruction type is apply instruction (immediate set in ONOS speak)
    private final TrafficTreatment treatment;

    private final DeviceId deviceId;

    public enum FlowType {
        STAT, LIGHTWEIGHT_STAT, REMOVED, MOD
    }

    private final FlowType type;

    private DriverHandler driverHandler;

    // NewAdaptiveFlowStatsCollector for AdaptiveFlowSampling mode,
    // null is not AFM mode, namely SimpleStatsCollector mode
    private NewAdaptiveFlowStatsCollector afsc;

    public MofFlowEntryBuilder(DeviceId deviceId, MofFlowStatsEntry entry, DriverHandler driverHandler) {
        this.stat = entry;
        this.selector = entry.getMatch();
        this.treatment = entry.getActions();
        this.deviceId = deviceId;
        // this.removed = null;
        // this.flowMod = null;
        this.type = FlowType.STAT;
        this.driverHandler = driverHandler;
        this.afsc = null;
        // this.lightWeightStat = null;
    }

    public MofFlowEntryBuilder withSetAfsc(NewAdaptiveFlowStatsCollector afsc) {
        this.afsc = afsc;
        return this;
    }

    public FlowEntry build(FlowEntryState... state) {
        try {
            switch (this.type) {
                case STAT:
                log.info("createFlowEntryFromStat");
                    return createFlowEntryFromStat();
                // case LIGHTWEIGHT_STAT:
                //     return createFlowEntryFromLightweightStat();
                // case REMOVED:
                //     return createFlowEntryForFlowRemoved();
                // case MOD:
                //     return createFlowEntryForFlowMod(state);
                default:
                    log.error("Unknown flow type : {}", this.type);
                    return null;
            }
        } catch (UnsupportedOperationException e) {
            log.warn("Error building flow entry", e);
            return null;
        }

    }

    private FlowEntry createFlowEntryFromStat() {

        FlowRule.Builder builder = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(stat.getPriority())
                .withIdleTimeout(stat.getIdleTimeout())
                .withCookie(stat.getCookie().getValue());
        if (stat.getVersion() != OFVersion.OF_10) {
            builder.forTable(stat.getTableId().getValue());
        }
        if (stat.getVersion().getWireVersion() < OFVersion.OF_15.getWireVersion()) {
            if (afsc != null) {
                FlowEntry.FlowLiveType liveType = afsc.calFlowLiveType(stat.getDurationSec());
                return new DefaultFlowEntry(builder.build(), FlowEntryState.ADDED,
                        SECONDS.toNanos(stat.getDurationSec())
                                + stat.getDurationNsec(),
                        NANOSECONDS,
                        liveType,
                        stat.getPacketCount().getValue(),
                        stat.getByteCount().getValue());
            } else {
                return new DefaultFlowEntry(builder.build(), FlowEntryState.ADDED,
                        stat.getDurationSec(),
                        stat.getPacketCount().getValue(),
                        stat.getByteCount().getValue());
            }
        }
        FlowStatParser statParser = new FlowStatParser(stat.getStats());
        if (afsc != null && statParser.isDurationReceived()) {
            FlowEntry.FlowLiveType liveType = afsc.calFlowLiveType(statParser.getDuration());
            return new DefaultFlowEntry(builder.build(), FlowEntryState.ADDED,
                    SECONDS.toNanos(statParser.getDuration())
                            + SECONDS.toNanos(statParser.getDuration()),
                    NANOSECONDS,
                    liveType,
                    statParser.getPacketCount(),
                    statParser.getByteCount());
        } else {
            return new DefaultFlowEntry(builder.build(), FlowEntryState.ADDED,
                    statParser.getDuration(),
                    statParser.getPacketCount(),
                    statParser.getByteCount());
        }

    }

}