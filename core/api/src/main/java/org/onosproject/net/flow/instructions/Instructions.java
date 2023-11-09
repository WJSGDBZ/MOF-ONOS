/*
 * Copyright 2014-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.net.flow.instructions;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;
import org.onlab.packet.EthType;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onosproject.core.GroupId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Lambda;
import org.onosproject.net.OchSignal;
import org.onosproject.net.OduSignalId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.StatTriggerField;
import org.onosproject.net.flow.StatTriggerFlag;
import org.onosproject.net.flow.instructions.L0ModificationInstruction.ModOchSignalInstruction;
import org.onosproject.net.flow.instructions.L1ModificationInstruction.ModOduSignalIdInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction.L3SubType;
import org.onosproject.net.flow.instructions.L3ModificationInstruction.ModIPInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction.ModArpIPInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction.ModArpEthInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction.ModArpOpInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction.ModIPv6FlowLabelInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction.ModTtlInstruction;
import org.onosproject.net.flow.instructions.L4ModificationInstruction.L4SubType;
import org.onosproject.net.flow.instructions.L4ModificationInstruction.ModTransportPortInstruction;
import org.onosproject.net.meter.MeterId;
import org.onosproject.net.pi.runtime.PiTableAction;

import org.onosproject.net.flow.instructions.protocol.*;
import org.onosproject.net.flow.criteria.*;

import org.onosproject.net.flow.TrafficSelector;
import io.netty.buffer.ByteBuf;
import java.util.Map;
import java.util.Objects;

import static com.google.common.base.MoreObjects.toStringHelper;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Factory class for creating various traffic treatment instructions.
 */
public final class Instructions {

    private static final String SEPARATOR = ":";

    // Ban construction
    private Instructions() {}

    public static DeleteProtocolInstruction createDeleteProtocol(int flag) {
        return new DeleteProtocolInstruction(flag);
    }

    public static SegRougtingInstruction createSegRougting() {
        return new SegRougtingInstruction();
    }

    public static MoveProtocolInstruction createMoveProtocol(int src, int dst){
        return new MoveProtocolInstruction(src, dst);
    }

    /**
     * Creates an output instruction using the specified port number. This can
     * include logical ports such as CONTROLLER, FLOOD, etc.
     *
     * @param number port number
     * @return output instruction
     */
    public static OutputInstruction createOutput(final PortNumber number) {
        checkNotNull(number, "PortNumber cannot be null");
        return new OutputInstruction(number);
    }

    public static GOTO_TABLEInstruction createGOTO_TABLE(final short tableId) {
        return new GOTO_TABLEInstruction(tableId);
    }

    /**
     * Creates a no action instruction.
     *
     * @return no action instruction
     */
    public static NoActionInstruction createNoAction() {
        return new NoActionInstruction();
    }

    /**
     * Creates a group instruction.
     *
     * @param groupId Group Id
     * @return group instruction
     */
    public static GroupInstruction createGroup(final GroupId groupId) {
        checkNotNull(groupId, "GroupId cannot be null");
        return new GroupInstruction(groupId);
    }

    /**
     * Creates a set-queue instruction.
     *
     * @param queueId Queue Id
     * @param port Port number
     * @return set-queue instruction
     */
    public static SetQueueInstruction setQueue(final long queueId, final PortNumber port) {
        return new SetQueueInstruction(queueId, port);
    }

    /**
     * Creates a meter instruction.
     *
     * @param meterId Meter Id
     * @return meter instruction
     */
    public static MeterInstruction meterTraffic(final MeterId meterId) {
        checkNotNull(meterId, "meter id cannot be null");
        return new MeterInstruction(meterId);
    }

    /**
     * Creates an L0 modification with the specified OCh signal.
     *
     * @param lambda OCh signal
     * @return an L0 modification
     */
    public static L0ModificationInstruction modL0Lambda(Lambda lambda) {
        checkNotNull(lambda, "L0 OCh signal cannot be null");

        if (lambda instanceof OchSignal) {
            return new ModOchSignalInstruction((OchSignal) lambda);
        } else {
            throw new UnsupportedOperationException(String.format("Unsupported type: %s", lambda));
        }
    }

    /**
     * Creates an L1 modification with the specified ODU signal Id.
     *
     * @param oduSignalId ODU Signal Id
     * @return a L1 modification
     */
    public static L1ModificationInstruction modL1OduSignalId(OduSignalId oduSignalId) {
        checkNotNull(oduSignalId, "L1 ODU signal ID cannot be null");
        return new ModOduSignalIdInstruction(oduSignalId);
    }
    /**
     * Creates a l2 src modification.
     *
     * @param addr the mac address to modify to
     * @return a l2 modification
     */
    public static L2ModificationInstruction modL2Src(MacAddress addr) {
        checkNotNull(addr, "Src l2 address cannot be null");
        return new L2ModificationInstruction.ModEtherInstruction(
                L2ModificationInstruction.L2SubType.ETH_SRC, addr);
    }

    /**
     * Creates a L2 dst modification.
     *
     * @param addr the mac address to modify to
     * @return a L2 modification
     */
    public static L2ModificationInstruction modL2Dst(MacAddress addr) {
        checkNotNull(addr, "Dst l2 address cannot be null");
        return new L2ModificationInstruction.ModEtherInstruction(
                L2ModificationInstruction.L2SubType.ETH_DST, addr);
    }

    /**
     * Creates a VLAN ID modification.
     *
     * @param vlanId the VLAN ID to modify to
     * @return a L2 modification
     */
    public static L2ModificationInstruction modVlanId(VlanId vlanId) {
        checkNotNull(vlanId, "VLAN id cannot be null");
        return new L2ModificationInstruction.ModVlanIdInstruction(vlanId);
    }

    /**
     * Creates a VLAN PCP modification.
     *
     * @param vlanPcp the PCP to modify to
     * @return a L2 modification
     */
    public static L2ModificationInstruction modVlanPcp(Byte vlanPcp) {
        checkNotNull(vlanPcp, "VLAN Pcp cannot be null");
        return new L2ModificationInstruction.ModVlanPcpInstruction(vlanPcp);
    }

    /**
     * Creates a MPLS label modification.
     *
     * @param mplsLabel MPLS label to set
     * @return a L2 Modification
     */
    public static L2ModificationInstruction modMplsLabel(MplsLabel mplsLabel) {
        checkNotNull(mplsLabel, "MPLS label cannot be null");
        return new L2ModificationInstruction.ModMplsLabelInstruction(mplsLabel);
    }

    /**
     * Creates a MPLS BOS bit modification.
     *
     * @param mplsBos MPLS BOS bit to set (true) or unset (false)
     * @return a L2 Modification
     */
    public static L2ModificationInstruction modMplsBos(boolean mplsBos) {
        return new L2ModificationInstruction.ModMplsBosInstruction(mplsBos);
    }

    /**
     * Creates a MPLS decrement TTL modification.
     *
     * @return a L2 Modification
     */
    public static L2ModificationInstruction decMplsTtl() {
        return new L2ModificationInstruction.ModMplsTtlInstruction();
    }

    /**
     * Creates a L3 IPv4 src modification.
     *
     * @param addr the IPv4 address to modify to
     * @return a L3 modification
     */
    public static L3ModificationInstruction modL3Src(IpAddress addr) {
        checkNotNull(addr, "Src l3 IPv4 address cannot be null");
        return new ModIPInstruction(L3SubType.IPV4_SRC, addr);
    }

    /**
     * Creates a L3 IPv4 dst modification.
     *
     * @param addr the IPv4 address to modify to
     * @return a L3 modification
     */
    public static L3ModificationInstruction modL3Dst(IpAddress addr) {
        checkNotNull(addr, "Dst l3 IPv4 address cannot be null");
        return new ModIPInstruction(L3SubType.IPV4_DST, addr);
    }

    /**
     * Creates a L3 IPv6 src modification.
     *
     * @param addr the IPv6 address to modify to
     * @return a L3 modification
     */
    public static L3ModificationInstruction modL3IPv6Src(IpAddress addr) {
        checkNotNull(addr, "Src l3 IPv6 address cannot be null");
        return new ModIPInstruction(L3SubType.IPV6_SRC, addr);
    }

    /**
     * Creates a L3 IPv6 dst modification.
     *
     * @param addr the IPv6 address to modify to
     * @return a L3 modification
     */
    public static L3ModificationInstruction modL3IPv6Dst(IpAddress addr) {
        checkNotNull(addr, "Dst l3 IPv6 address cannot be null");
        return new ModIPInstruction(L3SubType.IPV6_DST, addr);
    }

    /**
     * Creates a L3 IPv6 Flow Label modification.
     *
     * @param flowLabel the IPv6 flow label to modify to (20 bits)
     * @return a L3 modification
     */
    public static L3ModificationInstruction modL3IPv6FlowLabel(int flowLabel) {
        return new ModIPv6FlowLabelInstruction(flowLabel);
    }

    /**
     * Creates a L3 decrement TTL modification.
     *
     * @return a L3 modification
     */
    public static L3ModificationInstruction decNwTtl() {
        return new ModTtlInstruction(L3SubType.DEC_TTL);
    }

    /**
     * Creates a L3 copy TTL to outer header modification.
     *
     * @return a L3 modification
     */
    public static L3ModificationInstruction copyTtlOut() {
        return new ModTtlInstruction(L3SubType.TTL_OUT);
    }

    /**
     * Creates a L3 copy TTL to inner header modification.
     *
     * @return a L3 modification
     */
    public static L3ModificationInstruction copyTtlIn() {
        return new ModTtlInstruction(L3SubType.TTL_IN);
    }

    /**
     * Creates a L3 ARP IP src modification.
     *
     * @param addr the ip address to modify to
     * @return a L3 modification
     */
    public static L3ModificationInstruction modArpSpa(IpAddress addr) {
        checkNotNull(addr, "Src l3 ARP IP address cannot be null");
        return new ModArpIPInstruction(L3SubType.ARP_SPA, addr);
    }

    /**
     * Creates a l3 ARP Ether src modification.
     *
     * @param addr the mac address to modify to
     * @return a l3 modification
     */
    public static L3ModificationInstruction modArpSha(MacAddress addr) {
        checkNotNull(addr, "Src l3 ARP address cannot be null");
        return new ModArpEthInstruction(L3SubType.ARP_SHA, addr);
    }

    /**
     * Creates a L3 ARP IP src modification.
     *
     * @param addr the ip address to modify to
     * @return a L3 modification
     */
    public static L3ModificationInstruction modArpTpa(IpAddress addr) {
        checkNotNull(addr, "Dst l3 ARP IP address cannot be null");
        return new ModArpIPInstruction(L3SubType.ARP_TPA, addr);
    }

    /**
     * Creates a l3 ARP Ether src modification.
     *
     * @param addr the mac address to modify to
     * @return a l3 modification
     */
    public static L3ModificationInstruction modArpTha(MacAddress addr) {
        checkNotNull(addr, "Dst l3 ARP address cannot be null");
        return new ModArpEthInstruction(L3SubType.ARP_THA, addr);
    }

    /**
     * Creates a l3 ARP operation modification.
     *
     * @param op the ARP operation to modify to
     * @return a l3 modification
     */
    public static L3ModificationInstruction modL3ArpOp(short op) {
        return new ModArpOpInstruction(L3SubType.ARP_OP, op);
    }

    /**
     * Creates a push MPLS header instruction.
     *
     * @return a L2 modification.
     */
    public static Instruction pushMpls() {
        return new L2ModificationInstruction.ModMplsHeaderInstruction(
                L2ModificationInstruction.L2SubType.MPLS_PUSH,
                                          EthType.EtherType.MPLS_UNICAST.ethType());
    }

    /**
     * Creates a pop MPLS header instruction.
     *
     * @return a L2 modification.
     */
    public static Instruction popMpls() {
        return new L2ModificationInstruction.ModMplsHeaderInstruction(
                L2ModificationInstruction.L2SubType.MPLS_POP,
                EthType.EtherType.MPLS_UNICAST.ethType());
    }

    /**
     * Creates a pop MPLS header instruction with a particular ethertype.
     *
     * @param etherType Ethernet type to set
     * @return a L2 modification.
     */
    public static Instruction popMpls(EthType etherType) {
        checkNotNull(etherType, "Ethernet type cannot be null");
        return new L2ModificationInstruction.ModMplsHeaderInstruction(
                L2ModificationInstruction.L2SubType.MPLS_POP, etherType);
    }

    /**
     * Creates a pop VLAN header instruction.
     *
     * @return a L2 modification
     */
    public static Instruction popVlan() {
        return new L2ModificationInstruction.ModVlanHeaderInstruction(
                L2ModificationInstruction.L2SubType.VLAN_POP);
    }

    /**
     * Creates a push VLAN header instruction.
     *
     * @return a L2 modification
     */
    public static Instruction pushVlan() {
        return new L2ModificationInstruction.ModVlanHeaderInstruction(
                L2ModificationInstruction.L2SubType.VLAN_PUSH,
                EthType.EtherType.VLAN.ethType());
    }

    /**
     * Creates a push VLAN header instruction using the supplied Ethernet type.
     *
     * @param ethType the Ethernet type to use
     * @return a L2 modification
     */
    public static Instruction pushVlan(EthType ethType) {
        return new L2ModificationInstruction.ModVlanHeaderInstruction(
                L2ModificationInstruction.L2SubType.VLAN_PUSH,
                ethType);
    }

    /**
     * Sends the packet to the table id.
     *
     * @param tableId flow rule table id
     * @return table type transition instruction
     */
    public static Instruction transition(Integer tableId) {
        checkNotNull(tableId, "Table id cannot be null");
        return new TableTypeTransition(tableId);
    }

    /**
     * Writes metadata to associate with a packet.
     *
     * @param metadata the metadata value to write
     * @param metadataMask the bits to mask for the metadata value
     * @return metadata instruction
     */
    public static Instruction writeMetadata(long metadata, long metadataMask) {
        return new MetadataInstruction(metadata, metadataMask);
    }

    /**
     * Creates a Tunnel ID modification.
     *
     * @param tunnelId the Tunnel ID to modify to
     * @return a L2 modification
     */
    public static L2ModificationInstruction modTunnelId(long tunnelId) {
        return new L2ModificationInstruction.ModTunnelIdInstruction(tunnelId);
    }

    /**
     * Creates a TCP src modification.
     *
     * @param port the TCP port number to modify to
     * @return a L4 modification
     */
    public static L4ModificationInstruction modTcpSrc(TpPort port) {
       checkNotNull(port, "Src TCP port cannot be null");
       return new ModTransportPortInstruction(L4SubType.TCP_SRC, port);
    }

    /**
     * Creates a TCP dst modification.
     *
     * @param port the TCP port number to modify to
     * @return a L4 modification
     */
    public static L4ModificationInstruction modTcpDst(TpPort port) {
        checkNotNull(port, "Dst TCP port cannot be null");
        return new ModTransportPortInstruction(L4SubType.TCP_DST, port);
    }

    /**
     * Creates a UDP src modification.
     *
     * @param port the UDP port number to modify to
     * @return a L4 modification
     */
    public static L4ModificationInstruction modUdpSrc(TpPort port) {
        checkNotNull(port, "Src UDP port cannot be null");
        return new ModTransportPortInstruction(L4SubType.UDP_SRC, port);
    }

    /**
     * Creates a UDP dst modification.
     *
     * @param port the UDP port number to modify to
     * @return a L4 modification
     */
    public static L4ModificationInstruction modUdpDst(TpPort port) {
        checkNotNull(port, "Dst UDP port cannot be null");
        return new ModTransportPortInstruction(L4SubType.UDP_DST, port);
    }

    /**
     * Creates a protocol independent instruction.
     *
     * @param piTableAction protocol independent instruction
     * @return extension instruction
     */
    public static PiInstruction piTableAction(PiTableAction piTableAction) {
        checkNotNull(piTableAction, "PiTableAction instruction cannot be null");
        return new PiInstruction(piTableAction);
    }

    /**
     * Creates an IP DSCP modification.
     *
     * @param ipDscp the DSCP value to modify to
     * @return a L3 modification
     */
    public static Instruction modIpDscp(byte ipDscp) {
        return new L3ModificationInstruction.ModDscpInstruction(L3SubType.IP_DSCP, ipDscp);
    }

    /**
     * Creates an extension instruction.
     *
     * @param extension extension instruction
     * @param deviceId device ID
     * @return extension instruction
     */
    public static ExtensionInstructionWrapper extension(ExtensionTreatment extension,
                                                        DeviceId deviceId) {
        checkNotNull(extension, "Extension instruction cannot be null");
        checkNotNull(deviceId, "Device ID cannot be null");
        return new ExtensionInstructionWrapper(extension, deviceId);
    }

    /**
     * Creates a stat trigger instruction.
     *
     * @param statTriggerMap map keeps stat trigger threshold
     * @param flag stat trigger flag
     * @return stat trigger instruction
     */
    public static StatTriggerInstruction statTrigger(Map<StatTriggerField, Long> statTriggerMap,
                                                     StatTriggerFlag flag) {
        checkNotNull(statTriggerMap, "Stat trigger map cannot be null");
        checkNotNull(flag, "Stat trigger flag  cannot be null");
        return new StatTriggerInstruction(statTriggerMap, flag);
    }

    /**
     * Creates a truncate instruction.
     *
     * @param maxLen the maximum frame length in bytes, must be a positive integer
     * @return truncate instruction
     */
    public static TruncateInstruction truncate(int maxLen) {
        checkArgument(maxLen > 0, "Truncate max length must be a positive integer.");
        return new TruncateInstruction(maxLen);
    }

    /**
     *  No Action instruction.
     */
    public static final class NoActionInstruction implements Instruction {

        private NoActionInstruction() {}

        @Override
        public void write(ByteBuf c){

        }

        @Override
        public Type type() {
            return Type.NOACTION;
        }

        @Override
        public String toString() {
            return type().toString();
        }

        @Override
        public int hashCode() {
            return type().ordinal();
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof NoActionInstruction) {
                return true;
            }
            return false;
        }
    }

    /**
     *  Output Instruction.
     */
    public static final class OutputInstruction implements Instruction {
        private final PortNumber port;

        private OutputInstruction(PortNumber port) {
            this.port = port;
        }

        public static OutputInstruction readFrom(ByteBuf bb){
            byte type = bb.readByte();
            byte raw = bb.readByte();
            short len = bb.readShort();
            int port = bb.readInt();
            short maxlen = bb.readShort();
            bb.skipBytes(6); //pad

            return new OutputInstruction(PortNumber.portNumber(port));
        }

        @Override
        public void write(ByteBuf bb){
            // fixed value property type = 0
            bb.writeByte(0x0);
            // raw
            bb.writeByte(0xff);
            // len
            bb.writeShort(Short.reverseBytes((short)0x10));
            // port
            bb.writeInt(Integer.reverseBytes((int)this.port.toLong()));
            // maxlen
            bb.writeShort(0x0);
            //pad
            bb.writeZero(6);
        }

        public PortNumber port() {
            return port;
        }

        @Override
        public Type type() {
            return Type.OUTPUT;
        }

        @Override
        public String toString() {
            return type().toString() + SEPARATOR + port.toString();
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), port);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof OutputInstruction) {
                OutputInstruction that = (OutputInstruction) obj;
                return Objects.equals(port, that.port);

            }
            return false;
        }
    }


    public static final class GOTO_TABLEInstruction implements Instruction {
        private final short tableId;

        private GOTO_TABLEInstruction(short tableId) {
            this.tableId = tableId;
        }

        public static GOTO_TABLEInstruction readFrom(ByteBuf bb){
            byte type = bb.readByte();
            byte raw = bb.readByte();
            short len = bb.readShort();
            short tableId = bb.readByte();
            short maxlen = bb.readShort();
            bb.skipBytes(6); //pad

            return new GOTO_TABLEInstruction(tableId);
        }

        @Override
        public void write(ByteBuf bb){
            // fixed value property type = 0
            bb.writeByte((byte)58);
            // raw
            bb.writeByte(0xff);
            // len
            bb.writeShort(Short.reverseBytes((short)0x8));
            // tableId
            bb.writeByte((byte)tableId);
            //pad
            bb.writeZero(3);
        }

        public short tableId() {
            return tableId;
        }

        @Override
        public Type type() {
            return Type.GOTO_Table;
        }

        @Override
        public String toString() {
            return type().toString() + SEPARATOR + tableId;
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), tableId);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof GOTO_TABLEInstruction) {
                GOTO_TABLEInstruction that = (GOTO_TABLEInstruction) obj;
                return tableId == that.tableId;

            }
            return false;
        }
    }

    /**
     *  Group Instruction.
     */
    public static final class GroupInstruction implements Instruction {
        private final GroupId groupId;

        private GroupInstruction(GroupId groupId) {
            this.groupId = groupId;
        }
        @Override
        public void write(ByteBuf c){

        }
        public GroupId groupId() {
            return groupId;
        }

        @Override
        public Type type() {
            return Type.GROUP;
        }

        @Override
        public String toString() {
            return type().toString() + SEPARATOR + "0x" + Integer.toHexString(groupId.id());
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), groupId);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof GroupInstruction) {
                GroupInstruction that = (GroupInstruction) obj;
                return Objects.equals(groupId, that.groupId);

            }
            return false;
        }
    }

    /**
     *  Set-Queue Instruction.
     */
    public static final class SetQueueInstruction implements Instruction {
        private final long queueId;
        private final PortNumber port;

        private SetQueueInstruction(long queueId) {
            this.queueId = queueId;
            this.port = null;
        }

        private SetQueueInstruction(long queueId, PortNumber port) {
            this.queueId = queueId;
            this.port = port;
        }

        @Override
        public void write(ByteBuf c){

        }

        public long queueId() {
            return queueId;
        }

        public PortNumber port() {
            return port;
        }

        @Override
        public Type type() {
            return Type.QUEUE;
        }

        @Override
        public String toString() {
            MoreObjects.ToStringHelper toStringHelper = toStringHelper(type().toString());
            toStringHelper.add("queueId", queueId);

            if (port() != null) {
                toStringHelper.add("port", port);
            }
            return toStringHelper.toString();
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), queueId, port);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof SetQueueInstruction) {
                SetQueueInstruction that = (SetQueueInstruction) obj;
                return Objects.equals(queueId, that.queueId) && Objects.equals(port, that.port);

            }
            return false;
        }
    }

    /**
     * A meter instruction.
     */
    public static final class MeterInstruction implements Instruction {
        private final MeterId meterId;

        private MeterInstruction(MeterId meterId) {
            this.meterId = meterId;
        }

        public MeterId meterId() {
            return meterId;
        }

        @Override
        public void write(ByteBuf c){

        }

        @Override
        public Type type() {
            return Type.METER;
        }

        @Override
        public String toString() {
            return type().toString() + SEPARATOR + meterId.id();
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), meterId);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof MeterInstruction) {
                MeterInstruction that = (MeterInstruction) obj;
                return Objects.equals(meterId, that.meterId);

            }
            return false;
        }
    }

    /**
     *  Transition instruction.
     */
    public static class TableTypeTransition implements Instruction {
        private final Integer tableId;

        TableTypeTransition(Integer tableId) {
            this.tableId = tableId;
        }

        public static TableTypeTransition readFrom(ByteBuf bb){
            byte type = bb.readByte();
            byte raw = bb.readByte();
            short len = bb.readShort();
            int tableId = bb.readByte();
            bb.skipBytes(3); //pad

            return new TableTypeTransition(tableId);
        }

        @Override
        public void write(ByteBuf bb){
            // type 
            bb.writeByte((byte)58);
            // raw
            bb.writeByte(0xff);
            // len
            bb.writeShort(Short.reverseBytes((short)0x8));
            // tableId
            bb.writeByte(tableId.byteValue());
            //bb.writeByte(0x01);
            //pad
            bb.writeZero(3);
        }

        @Override
        public Type type() {
            return Type.TABLE;
        }

        public Integer tableId() {
            return this.tableId;
        }

        @Override
        public String toString() {
            return type().toString() + SEPARATOR + this.tableId;
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), tableId);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof TableTypeTransition) {
                TableTypeTransition that = (TableTypeTransition) obj;
                return Objects.equals(tableId, that.tableId);

            }
            return false;
        }
    }

    /**
     *  Metadata instruction.
     */
    public static class MetadataInstruction implements Instruction {
        private final long metadata;
        private final long metadataMask;

        MetadataInstruction(long metadata, long metadataMask) {
            this.metadata = metadata;
            this.metadataMask = metadataMask;
        }

        @Override
        public void write(ByteBuf c){

        }

        @Override
        public Type type() {
            return Type.METADATA;
        }

        public long metadata() {
            return this.metadata;
        }

        public long metadataMask() {
            return this.metadataMask;
        }

        @Override
        public String toString() {
            return type().toString() + SEPARATOR +
                    Long.toHexString(this.metadata) + "/" +
                    Long.toHexString(this.metadataMask);
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), metadata, metadataMask);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof MetadataInstruction) {
                MetadataInstruction that = (MetadataInstruction) obj;
                return Objects.equals(metadata, that.metadata) &&
                        Objects.equals(metadataMask, that.metadataMask);

            }
            return false;
        }
    }

    /**
     *  Extension instruction.
     */
    public static class ExtensionInstructionWrapper implements Instruction {
        private final ExtensionTreatment extensionTreatment;
        private final DeviceId deviceId;

        ExtensionInstructionWrapper(ExtensionTreatment extension, DeviceId deviceId) {
            extensionTreatment = extension;
            this.deviceId = deviceId;
        }

        public ExtensionTreatment extensionInstruction() {
            return extensionTreatment;
        }

        @Override
        public void write(ByteBuf c){

        }

        public DeviceId deviceId() {
            return deviceId;
        }

        @Override
        public Type type() {
            return Type.EXTENSION;
        }

        @Override
        public String toString() {
            return type().toString() + SEPARATOR + deviceId + "/" + extensionTreatment;
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), extensionTreatment, deviceId);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof ExtensionInstructionWrapper) {
                ExtensionInstructionWrapper that = (ExtensionInstructionWrapper) obj;
                return Objects.equals(extensionTreatment, that.extensionTreatment)
                        && Objects.equals(deviceId, that.deviceId);

            }
            return false;
        }
    }

    public static class StatTriggerInstruction implements Instruction {
        private Map<StatTriggerField, Long> statTriggerFieldMap;
        private StatTriggerFlag statTriggerFlag;


        StatTriggerInstruction(Map<StatTriggerField, Long> statTriggerMap,
                                      StatTriggerFlag flag) {
            this.statTriggerFieldMap = ImmutableMap.copyOf(statTriggerMap);
            this.statTriggerFlag = flag;
        }

        @Override
        public void write(ByteBuf c){

        }

        public Map<StatTriggerField, Long> getStatTriggerFieldMap() {
            return statTriggerFieldMap;
        }

        public StatTriggerFlag getStatTriggerFlag() {
            return statTriggerFlag;
        }

        public Long getStatValue(StatTriggerField field) {
            return statTriggerFieldMap.get(field);
        }

        @Override
        public Type type() {
            return Type.STAT_TRIGGER;
        }

        @Override
        public String toString() {
            return "StatTriggerInstruction{" +
                    "statTriggerFieldMap=" + statTriggerFieldMap +
                    ", statTriggerFlag=" + statTriggerFlag +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            StatTriggerInstruction that = (StatTriggerInstruction) o;

            if (!Objects.equals(statTriggerFieldMap, that.statTriggerFieldMap)) {
                return false;
            }

            return statTriggerFlag == that.statTriggerFlag;
        }

        @Override
        public int hashCode() {
            int result = statTriggerFieldMap != null ? statTriggerFieldMap.hashCode() : 0;
            result = 31 * result + (statTriggerFlag != null ? statTriggerFlag.hashCode() : 0);
            return result;
        }
    }

    public static final class TruncateInstruction implements Instruction {
        private int maxLen;

        public TruncateInstruction(int maxLen) {
            this.maxLen = maxLen;
        }

        public int maxLen() {
            return maxLen;
        }

        @Override
        public void write(ByteBuf c){

        }

        @Override
        public Type type() {
            return Type.TRUNCATE;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            TruncateInstruction that = (TruncateInstruction) o;
            return maxLen == that.maxLen;
        }

        @Override
        public int hashCode() {
            return com.google.common.base.Objects.hashCode(maxLen);
        }

        @Override
        public String toString() {
            return type() + SEPARATOR + maxLen;
        }
    }


    public static class DeleteProtocolInstruction implements Instruction {
        private final int flag;

        DeleteProtocolInstruction(int flag) {
            this.flag = flag;
        }

        public static DeleteProtocolInstruction readFrom(ByteBuf bb){
            byte type = bb.readByte();
            byte raw = bb.readByte();
            short len = bb.readShort();
            int protocol_type = bb.readInt();
            
            return createDeleteProtocol(protocol_type);
        }

        @Override
        public void write(ByteBuf bb){
            // type 
            bb.writeByte((byte)60);
            // raw
            bb.writeByte(0xff);
            // len
            bb.writeShort(Short.reverseBytes((short)8)); 
            // flag
            bb.writeInt(Integer.reverseBytes(flag));
        }

        @Override
        public Type type() {
            return Type.DELETE_PROTOCOL;
        }

        @Override
        public String toString() {
            return "DeleteProtocol[" + Protocol.ProtocolFormatByType(flag) + "]";
        }

        @Override
        public int hashCode() {
            return Objects.hash(flag);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof DeleteProtocolInstruction) {
                DeleteProtocolInstruction that = (DeleteProtocolInstruction) obj;
                return Objects.equals(flag, that.flag);

            }
            return false;
        }
    }

    public static class SegRougtingInstruction implements Instruction {

        SegRougtingInstruction() {}

        public static SegRougtingInstruction readFrom(ByteBuf bb){
            byte type = bb.readByte();
            byte raw = bb.readByte();
            short len = bb.readShort();
            bb.skipBytes(4);

            return createSegRougting();
        }

        @Override
        public void write(ByteBuf bb){
            // type 
            bb.writeByte((byte)65);
            // raw
            bb.writeByte(0xff);
            // len
            bb.writeShort(Short.reverseBytes((short)8)); 
            // pad
            bb.writeZero(4);
        }

        @Override
        public Type type() {
            return Type.SEG_ROUGTING;
        }

        @Override
        public String toString() {
            return "SegRougting[]";
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal());
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof SegRougtingInstruction) {
                return true;

            }
            return false;
        }
    }

    public static class MoveProtocolInstruction implements Instruction {
        private final int src_flag;
        private final int dst_flag;

        MoveProtocolInstruction(int src, int dst) {
            this.src_flag = src;
            this.dst_flag = dst;
        }

        public static MoveProtocolInstruction readFrom(ByteBuf bb){
            byte type = bb.readByte();
            byte raw = bb.readByte();
            short len = bb.readShort();
            int src = bb.readInt();
            int dst = bb.readInt();

            bb.skipBytes(4);
            return createMoveProtocol(src, dst);
        }

        @Override
        public void write(ByteBuf bb){
            // type 
            bb.writeByte((byte)66);
            // raw
            bb.writeByte(0xff);
            // len
            bb.writeShort(Short.reverseBytes((short)16)); 
            // src
            bb.writeInt(Integer.reverseBytes(src_flag));
            // dst
            bb.writeInt(Integer.reverseBytes(dst_flag));

            bb.writeZero(4);
        }

        @Override
        public Type type() {
            return Type.MOVE_PROTOCOL;
        }

        @Override
        public String toString() {
            return "MoveProtocol [src: " + Protocol.ProtocolFormatByType(src_flag) + ", dst: " +  Protocol.ProtocolFormatByType(dst_flag) + "]";
        }

        @Override
        public int hashCode() {
            return Objects.hash(src_flag, dst_flag);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof MoveProtocolInstruction) {
                MoveProtocolInstruction that = (MoveProtocolInstruction) obj;
                return Objects.equals(src_flag, that.src_flag) && Objects.equals(dst_flag, that.dst_flag);

            }
            return false;
        }
    }

    public static AddProtocolInstruction createAddProtocol(int flag, Protocol protocol) {
        checkNotNull(protocol, "protocol cannot be null");
        return new AddProtocolInstruction(flag, protocol);
    }

    public static AddProtocolInstruction createAddProtocol(String protocol, TrafficSelector selector) {
        int flag = Protocol.ProtocolFormatByString(protocol);
        switch(flag){
            case Protocol.MAC:
                checkNotNull(selector, "selector cannot be null");
                Mac_DstCriterion MAC_mac_dst = (Mac_DstCriterion)selector.getCriterion(Criterion.Type.MAC_DST);
                checkNotNull(MAC_mac_dst, "Action ADD_PROTOCOL need MAC_DST field");
                Mac_SrcCriterion MAC_mac_src = (Mac_SrcCriterion)selector.getCriterion(Criterion.Type.MAC_SRC);
                checkNotNull(MAC_mac_src, "Action ADD_PROTOCOL need MAC_SRC field");
                return new AddProtocolInstruction(flag, new Mac_Protocol(MAC_mac_dst, MAC_mac_src));
            case Protocol.VLAN1:
                checkNotNull(selector, "selector cannot be null");
                Vlan1_TpidCriterion VLAN1_vlan1_tpid = (Vlan1_TpidCriterion)selector.getCriterion(Criterion.Type.VLAN1_TPID);
                checkNotNull(VLAN1_vlan1_tpid, "Action ADD_PROTOCOL need VLAN1_TPID field");
                Vlan1_QidCriterion VLAN1_vlan1_qid = (Vlan1_QidCriterion)selector.getCriterion(Criterion.Type.VLAN1_QID);
                checkNotNull(VLAN1_vlan1_qid, "Action ADD_PROTOCOL need VLAN1_QID field");
                return new AddProtocolInstruction(flag, new Vlan1_Protocol(VLAN1_vlan1_tpid, VLAN1_vlan1_qid));
            case Protocol.VLAN2:
                checkNotNull(selector, "selector cannot be null");
                Vlan2_TpidCriterion VLAN2_vlan2_tpid = (Vlan2_TpidCriterion)selector.getCriterion(Criterion.Type.VLAN2_TPID);
                checkNotNull(VLAN2_vlan2_tpid, "Action ADD_PROTOCOL need VLAN2_TPID field");
                Vlan2_QidCriterion VLAN2_vlan2_qid = (Vlan2_QidCriterion)selector.getCriterion(Criterion.Type.VLAN2_QID);
                checkNotNull(VLAN2_vlan2_qid, "Action ADD_PROTOCOL need VLAN2_QID field");
                return new AddProtocolInstruction(flag, new Vlan2_Protocol(VLAN2_vlan2_tpid, VLAN2_vlan2_qid));
            case Protocol.DL:
                checkNotNull(selector, "selector cannot be null");
                Dl_TypeCriterion DL_dl_type = (Dl_TypeCriterion)selector.getCriterion(Criterion.Type.DL_TYPE);
                checkNotNull(DL_dl_type, "Action ADD_PROTOCOL need DL_TYPE field");
                return new AddProtocolInstruction(flag, new Dl_Protocol(DL_dl_type));
            case Protocol.IPV4_E:
                checkNotNull(selector, "selector cannot be null");
                Ver_Hl_ECriterion IPV4_E_ver_hl_e = (Ver_Hl_ECriterion)selector.getCriterion(Criterion.Type.VER_HL_E);
                checkNotNull(IPV4_E_ver_hl_e, "Action ADD_PROTOCOL need VER_HL_E field");
                Tos_ECriterion IPV4_E_tos_e = (Tos_ECriterion)selector.getCriterion(Criterion.Type.TOS_E);
                checkNotNull(IPV4_E_tos_e, "Action ADD_PROTOCOL need TOS_E field");
                Tot_Len_ECriterion IPV4_E_tot_len_e = (Tot_Len_ECriterion)selector.getCriterion(Criterion.Type.TOT_LEN_E);
                checkNotNull(IPV4_E_tot_len_e, "Action ADD_PROTOCOL need TOT_LEN_E field");
                Ip_Id_ECriterion IPV4_E_ip_id_e = (Ip_Id_ECriterion)selector.getCriterion(Criterion.Type.IP_ID_E);
                checkNotNull(IPV4_E_ip_id_e, "Action ADD_PROTOCOL need IP_ID_E field");
                Frag_Off_ECriterion IPV4_E_frag_off_e = (Frag_Off_ECriterion)selector.getCriterion(Criterion.Type.FRAG_OFF_E);
                checkNotNull(IPV4_E_frag_off_e, "Action ADD_PROTOCOL need FRAG_OFF_E field");
                Ttl_ECriterion IPV4_E_ttl_e = (Ttl_ECriterion)selector.getCriterion(Criterion.Type.TTL_E);
                checkNotNull(IPV4_E_ttl_e, "Action ADD_PROTOCOL need TTL_E field");
                Ipv4_E_TypeCriterion IPV4_E_ipv4_e_type = (Ipv4_E_TypeCriterion)selector.getCriterion(Criterion.Type.IPV4_E_TYPE);
                checkNotNull(IPV4_E_ipv4_e_type, "Action ADD_PROTOCOL need IPV4_E_TYPE field");
                Ip_Check_ECriterion IPV4_E_ip_check_e = (Ip_Check_ECriterion)selector.getCriterion(Criterion.Type.IP_CHECK_E);
                checkNotNull(IPV4_E_ip_check_e, "Action ADD_PROTOCOL need IP_CHECK_E field");
                Ip_Saddr_ECriterion IPV4_E_ip_saddr_e = (Ip_Saddr_ECriterion)selector.getCriterion(Criterion.Type.IP_SADDR_E);
                checkNotNull(IPV4_E_ip_saddr_e, "Action ADD_PROTOCOL need IP_SADDR_E field");
                Ip_Daddr_ECriterion IPV4_E_ip_daddr_e = (Ip_Daddr_ECriterion)selector.getCriterion(Criterion.Type.IP_DADDR_E);
                checkNotNull(IPV4_E_ip_daddr_e, "Action ADD_PROTOCOL need IP_DADDR_E field");
                return new AddProtocolInstruction(flag, new Ipv4_E_Protocol(IPV4_E_ver_hl_e, IPV4_E_tos_e, IPV4_E_tot_len_e, IPV4_E_ip_id_e, IPV4_E_frag_off_e, IPV4_E_ttl_e, IPV4_E_ipv4_e_type, IPV4_E_ip_check_e, IPV4_E_ip_saddr_e, IPV4_E_ip_daddr_e));
            case Protocol.IPV6_E:
                checkNotNull(selector, "selector cannot be null");
                Ipv6_Ver_Tp_Flb_ECriterion IPV6_E_ipv6_ver_tp_flb_e = (Ipv6_Ver_Tp_Flb_ECriterion)selector.getCriterion(Criterion.Type.IPV6_VER_TP_FLB_E);
                checkNotNull(IPV6_E_ipv6_ver_tp_flb_e, "Action ADD_PROTOCOL need IPV6_VER_TP_FLB_E field");
                Ipv6_Plen_ECriterion IPV6_E_ipv6_plen_e = (Ipv6_Plen_ECriterion)selector.getCriterion(Criterion.Type.IPV6_PLEN_E);
                checkNotNull(IPV6_E_ipv6_plen_e, "Action ADD_PROTOCOL need IPV6_PLEN_E field");
                Ipv6_E_TypeCriterion IPV6_E_ipv6_e_type = (Ipv6_E_TypeCriterion)selector.getCriterion(Criterion.Type.IPV6_E_TYPE);
                checkNotNull(IPV6_E_ipv6_e_type, "Action ADD_PROTOCOL need IPV6_E_TYPE field");
                Ipv6_Hlmt_ECriterion IPV6_E_ipv6_hlmt_e = (Ipv6_Hlmt_ECriterion)selector.getCriterion(Criterion.Type.IPV6_HLMT_E);
                checkNotNull(IPV6_E_ipv6_hlmt_e, "Action ADD_PROTOCOL need IPV6_HLMT_E field");
                Ipv6_Src_ECriterion IPV6_E_ipv6_src_e = (Ipv6_Src_ECriterion)selector.getCriterion(Criterion.Type.IPV6_SRC_E);
                checkNotNull(IPV6_E_ipv6_src_e, "Action ADD_PROTOCOL need IPV6_SRC_E field");
                Ipv6_Dst_ECriterion IPV6_E_ipv6_dst_e = (Ipv6_Dst_ECriterion)selector.getCriterion(Criterion.Type.IPV6_DST_E);
                checkNotNull(IPV6_E_ipv6_dst_e, "Action ADD_PROTOCOL need IPV6_DST_E field");
                return new AddProtocolInstruction(flag, new Ipv6_E_Protocol(IPV6_E_ipv6_ver_tp_flb_e, IPV6_E_ipv6_plen_e, IPV6_E_ipv6_e_type, IPV6_E_ipv6_hlmt_e, IPV6_E_ipv6_src_e, IPV6_E_ipv6_dst_e));
            case Protocol.UDP:
                checkNotNull(selector, "selector cannot be null");
                Udp_SourceCriterion UDP_udp_source = (Udp_SourceCriterion)selector.getCriterion(Criterion.Type.UDP_SOURCE);
                checkNotNull(UDP_udp_source, "Action ADD_PROTOCOL need UDP_SOURCE field");
                Udp_DestCriterion UDP_udp_dest = (Udp_DestCriterion)selector.getCriterion(Criterion.Type.UDP_DEST);
                checkNotNull(UDP_udp_dest, "Action ADD_PROTOCOL need UDP_DEST field");
                LenCriterion UDP_len = (LenCriterion)selector.getCriterion(Criterion.Type.LEN);
                checkNotNull(UDP_len, "Action ADD_PROTOCOL need LEN field");
                Udp_CheckCriterion UDP_udp_check = (Udp_CheckCriterion)selector.getCriterion(Criterion.Type.UDP_CHECK);
                checkNotNull(UDP_udp_check, "Action ADD_PROTOCOL need UDP_CHECK field");
                return new AddProtocolInstruction(flag, new Udp_Protocol(UDP_udp_source, UDP_udp_dest, UDP_len, UDP_udp_check));
            case Protocol.SRV6_1:
                checkNotNull(selector, "selector cannot be null");
                Srv6_TypeCriterion SRV6_1_srv6_type = (Srv6_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_TYPE);
                checkNotNull(SRV6_1_srv6_type, "Action ADD_PROTOCOL need SRV6_TYPE field");
                Srv6_Hdr_Ext_LenCriterion SRV6_1_srv6_hdr_ext_len = (Srv6_Hdr_Ext_LenCriterion)selector.getCriterion(Criterion.Type.SRV6_HDR_EXT_LEN);
                checkNotNull(SRV6_1_srv6_hdr_ext_len, "Action ADD_PROTOCOL need SRV6_HDR_EXT_LEN field");
                Srv6_Routing_TypeCriterion SRV6_1_srv6_routing_Type = (Srv6_Routing_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_ROUTING_TYPE);
                checkNotNull(SRV6_1_srv6_routing_Type, "Action ADD_PROTOCOL need SRV6_ROUTING_TYPE field");
                Srv6_Segments_LeftCriterion SRV6_1_srv6_segments_left = (Srv6_Segments_LeftCriterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTS_LEFT);
                checkNotNull(SRV6_1_srv6_segments_left, "Action ADD_PROTOCOL need SRV6_SEGMENTS_LEFT field");
                Srv6_Last_EntyCriterion SRV6_1_srv6_last_enty = (Srv6_Last_EntyCriterion)selector.getCriterion(Criterion.Type.SRV6_LAST_ENTY);
                checkNotNull(SRV6_1_srv6_last_enty, "Action ADD_PROTOCOL need SRV6_LAST_ENTY field");
                Srv6_FlagsCriterion SRV6_1_srv6_flags = (Srv6_FlagsCriterion)selector.getCriterion(Criterion.Type.SRV6_FLAGS);
                checkNotNull(SRV6_1_srv6_flags, "Action ADD_PROTOCOL need SRV6_FLAGS field");
                Srv6_TagCriterion SRV6_1_srv6_tag = (Srv6_TagCriterion)selector.getCriterion(Criterion.Type.SRV6_TAG);
                checkNotNull(SRV6_1_srv6_tag, "Action ADD_PROTOCOL need SRV6_TAG field");
                Srv6_Segmentlist1Criterion SRV6_1_srv6_segmentlist1 = (Srv6_Segmentlist1Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST1);
                checkNotNull(SRV6_1_srv6_segmentlist1, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST1 field");
                return new AddProtocolInstruction(flag, new Srv6_1_Protocol(SRV6_1_srv6_type, SRV6_1_srv6_hdr_ext_len, SRV6_1_srv6_routing_Type, SRV6_1_srv6_segments_left, SRV6_1_srv6_last_enty, SRV6_1_srv6_flags, SRV6_1_srv6_tag, SRV6_1_srv6_segmentlist1));
            case Protocol.SRV6_2:
                checkNotNull(selector, "selector cannot be null");
                Srv6_TypeCriterion SRV6_2_srv6_type = (Srv6_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_TYPE);
                checkNotNull(SRV6_2_srv6_type, "Action ADD_PROTOCOL need SRV6_TYPE field");
                Srv6_Hdr_Ext_LenCriterion SRV6_2_srv6_hdr_ext_len = (Srv6_Hdr_Ext_LenCriterion)selector.getCriterion(Criterion.Type.SRV6_HDR_EXT_LEN);
                checkNotNull(SRV6_2_srv6_hdr_ext_len, "Action ADD_PROTOCOL need SRV6_HDR_EXT_LEN field");
                Srv6_Routing_TypeCriterion SRV6_2_srv6_routing_Type = (Srv6_Routing_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_ROUTING_TYPE);
                checkNotNull(SRV6_2_srv6_routing_Type, "Action ADD_PROTOCOL need SRV6_ROUTING_TYPE field");
                Srv6_Segments_LeftCriterion SRV6_2_srv6_segments_left = (Srv6_Segments_LeftCriterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTS_LEFT);
                checkNotNull(SRV6_2_srv6_segments_left, "Action ADD_PROTOCOL need SRV6_SEGMENTS_LEFT field");
                Srv6_Last_EntyCriterion SRV6_2_srv6_last_enty = (Srv6_Last_EntyCriterion)selector.getCriterion(Criterion.Type.SRV6_LAST_ENTY);
                checkNotNull(SRV6_2_srv6_last_enty, "Action ADD_PROTOCOL need SRV6_LAST_ENTY field");
                Srv6_FlagsCriterion SRV6_2_srv6_flags = (Srv6_FlagsCriterion)selector.getCriterion(Criterion.Type.SRV6_FLAGS);
                checkNotNull(SRV6_2_srv6_flags, "Action ADD_PROTOCOL need SRV6_FLAGS field");
                Srv6_TagCriterion SRV6_2_srv6_tag = (Srv6_TagCriterion)selector.getCriterion(Criterion.Type.SRV6_TAG);
                checkNotNull(SRV6_2_srv6_tag, "Action ADD_PROTOCOL need SRV6_TAG field");
                Srv6_Segmentlist1Criterion SRV6_2_srv6_segmentlist1 = (Srv6_Segmentlist1Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST1);
                checkNotNull(SRV6_2_srv6_segmentlist1, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST1 field");
                Srv6_Segmentlist2Criterion SRV6_2_srv6_segmentlist2 = (Srv6_Segmentlist2Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST2);
                checkNotNull(SRV6_2_srv6_segmentlist2, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST2 field");
                return new AddProtocolInstruction(flag, new Srv6_2_Protocol(SRV6_2_srv6_type, SRV6_2_srv6_hdr_ext_len, SRV6_2_srv6_routing_Type, SRV6_2_srv6_segments_left, SRV6_2_srv6_last_enty, SRV6_2_srv6_flags, SRV6_2_srv6_tag, SRV6_2_srv6_segmentlist1, SRV6_2_srv6_segmentlist2));
            case Protocol.SRV6_3:
                checkNotNull(selector, "selector cannot be null");
                Srv6_TypeCriterion SRV6_3_srv6_type = (Srv6_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_TYPE);
                checkNotNull(SRV6_3_srv6_type, "Action ADD_PROTOCOL need SRV6_TYPE field");
                Srv6_Hdr_Ext_LenCriterion SRV6_3_srv6_hdr_ext_len = (Srv6_Hdr_Ext_LenCriterion)selector.getCriterion(Criterion.Type.SRV6_HDR_EXT_LEN);
                checkNotNull(SRV6_3_srv6_hdr_ext_len, "Action ADD_PROTOCOL need SRV6_HDR_EXT_LEN field");
                Srv6_Routing_TypeCriterion SRV6_3_srv6_routing_Type = (Srv6_Routing_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_ROUTING_TYPE);
                checkNotNull(SRV6_3_srv6_routing_Type, "Action ADD_PROTOCOL need SRV6_ROUTING_TYPE field");
                Srv6_Segments_LeftCriterion SRV6_3_srv6_segments_left = (Srv6_Segments_LeftCriterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTS_LEFT);
                checkNotNull(SRV6_3_srv6_segments_left, "Action ADD_PROTOCOL need SRV6_SEGMENTS_LEFT field");
                Srv6_Last_EntyCriterion SRV6_3_srv6_last_enty = (Srv6_Last_EntyCriterion)selector.getCriterion(Criterion.Type.SRV6_LAST_ENTY);
                checkNotNull(SRV6_3_srv6_last_enty, "Action ADD_PROTOCOL need SRV6_LAST_ENTY field");
                Srv6_FlagsCriterion SRV6_3_srv6_flags = (Srv6_FlagsCriterion)selector.getCriterion(Criterion.Type.SRV6_FLAGS);
                checkNotNull(SRV6_3_srv6_flags, "Action ADD_PROTOCOL need SRV6_FLAGS field");
                Srv6_TagCriterion SRV6_3_srv6_tag = (Srv6_TagCriterion)selector.getCriterion(Criterion.Type.SRV6_TAG);
                checkNotNull(SRV6_3_srv6_tag, "Action ADD_PROTOCOL need SRV6_TAG field");
                Srv6_Segmentlist1Criterion SRV6_3_srv6_segmentlist1 = (Srv6_Segmentlist1Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST1);
                checkNotNull(SRV6_3_srv6_segmentlist1, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST1 field");
                Srv6_Segmentlist2Criterion SRV6_3_srv6_segmentlist2 = (Srv6_Segmentlist2Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST2);
                checkNotNull(SRV6_3_srv6_segmentlist2, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST2 field");
                Srv6_Segmentlist3Criterion SRV6_3_srv6_segmentlist3 = (Srv6_Segmentlist3Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST3);
                checkNotNull(SRV6_3_srv6_segmentlist3, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST3 field");
                return new AddProtocolInstruction(flag, new Srv6_3_Protocol(SRV6_3_srv6_type, SRV6_3_srv6_hdr_ext_len, SRV6_3_srv6_routing_Type, SRV6_3_srv6_segments_left, SRV6_3_srv6_last_enty, SRV6_3_srv6_flags, SRV6_3_srv6_tag, SRV6_3_srv6_segmentlist1, SRV6_3_srv6_segmentlist2, SRV6_3_srv6_segmentlist3));
            case Protocol.IPV6_I:
                checkNotNull(selector, "selector cannot be null");
                Ipv6_Ver_Tp_Flb_ICriterion IPV6_I_ipv6_ver_tp_flb_i = (Ipv6_Ver_Tp_Flb_ICriterion)selector.getCriterion(Criterion.Type.IPV6_VER_TP_FLB_I);
                checkNotNull(IPV6_I_ipv6_ver_tp_flb_i, "Action ADD_PROTOCOL need IPV6_VER_TP_FLB_I field");
                Ipv6_Plen_ICriterion IPV6_I_ipv6_plen_i = (Ipv6_Plen_ICriterion)selector.getCriterion(Criterion.Type.IPV6_PLEN_I);
                checkNotNull(IPV6_I_ipv6_plen_i, "Action ADD_PROTOCOL need IPV6_PLEN_I field");
                Ipv6_I_TypeCriterion IPV6_I_ipv6_i_type = (Ipv6_I_TypeCriterion)selector.getCriterion(Criterion.Type.IPV6_I_TYPE);
                checkNotNull(IPV6_I_ipv6_i_type, "Action ADD_PROTOCOL need IPV6_I_TYPE field");
                Ipv6_Hlmt_ICriterion IPV6_I_ipv6_hlmt_i = (Ipv6_Hlmt_ICriterion)selector.getCriterion(Criterion.Type.IPV6_HLMT_I);
                checkNotNull(IPV6_I_ipv6_hlmt_i, "Action ADD_PROTOCOL need IPV6_HLMT_I field");
                Ipv6_Src_ICriterion IPV6_I_ipv6_src_i = (Ipv6_Src_ICriterion)selector.getCriterion(Criterion.Type.IPV6_SRC_I);
                checkNotNull(IPV6_I_ipv6_src_i, "Action ADD_PROTOCOL need IPV6_SRC_I field");
                Ipv6_Dst_ICriterion IPV6_I_ipv6_dst_i = (Ipv6_Dst_ICriterion)selector.getCriterion(Criterion.Type.IPV6_DST_I);
                checkNotNull(IPV6_I_ipv6_dst_i, "Action ADD_PROTOCOL need IPV6_DST_I field");
                return new AddProtocolInstruction(flag, new Ipv6_I_Protocol(IPV6_I_ipv6_ver_tp_flb_i, IPV6_I_ipv6_plen_i, IPV6_I_ipv6_i_type, IPV6_I_ipv6_hlmt_i, IPV6_I_ipv6_src_i, IPV6_I_ipv6_dst_i));
            default:
                throw new UnsupportedOperationException("Action ADD_PROTOCOL add a unsupported protocol");
        }
    }

    public static class AddProtocolInstruction implements Instruction {
        private final int flag;
        private final Protocol protocol;

        AddProtocolInstruction(int flag, Protocol protocol) {
            this.flag = flag;
            this.protocol = protocol;
        }

        public static AddProtocolInstruction readFrom(ByteBuf bb){
            int start = bb.readerIndex();

            byte type = bb.readByte();
            byte raw = bb.readByte();
            short len = bb.readShort();
            int protocol_type = bb.readInt();
            Protocol result = null;
            switch(protocol_type){
                case Protocol.MAC:
                    result = Mac_Protocol.read(bb);
                    break;
                case Protocol.VLAN1:
                    result = Vlan1_Protocol.read(bb);
                    break;
                case Protocol.VLAN2:
                    result = Vlan2_Protocol.read(bb);
                    break;
                case Protocol.DL:
                    result = Dl_Protocol.read(bb);
                    break;
                case Protocol.IPV4_E:
                    result = Ipv4_E_Protocol.read(bb);
                    break;
                case Protocol.IPV6_E:
                    result = Ipv6_E_Protocol.read(bb);
                    break;
                case Protocol.UDP:
                    result = Udp_Protocol.read(bb);
                    break;
                case Protocol.SRV6_1:
                    result = Srv6_1_Protocol.read(bb);
                    break;
                case Protocol.SRV6_2:
                    result = Srv6_2_Protocol.read(bb);
                    break;
                case Protocol.SRV6_3:
                    result = Srv6_3_Protocol.read(bb);
                    break;
                case Protocol.IPV6_I:
                    result = Ipv6_I_Protocol.read(bb);
                    break;
                default:
                    throw new UnsupportedOperationException("Action ADD_PROTOCOL add a unsupported protocol");
            }

            int pad = 8 - ((bb.readerIndex() - start) % 8);
            bb.skipBytes(pad); 

            return createAddProtocol(protocol_type, result);
        }

        @Override
        public void write(ByteBuf bb){
            int start = bb.writerIndex();
            // type 
            bb.writeByte((byte)59);
            // raw
            bb.writeByte(0xff);
            // len
            int lengthIndex = bb.writerIndex();
            bb.writeShort((short)0);
            // flag
            bb.writeInt(Integer.reverseBytes(flag));
            // protocol
            protocol.write(bb);
            //pad
            int pad = 8 - ((bb.writerIndex() - start) % 8);
            bb.writeZero(pad);

            int length = bb.writerIndex() - start;
            bb.setShort(lengthIndex, Short.reverseBytes((short)length));
        }

        @Override
        public Type type() {
            return Type.ADD_PROTOCOL;
        }

        @Override
        public String toString() {
            return "AddProtocol[" + protocol.toString() + "]";
        }

        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), flag);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof AddProtocolInstruction) {
                AddProtocolInstruction that = (AddProtocolInstruction) obj;
                return Objects.equals(flag, that.flag) && Objects.equals(protocol, that.protocol);

            }
            return false;
        }
    }

    public static ModFieldInstruction createModField(int flag, Protocol protocol) {
        checkNotNull(protocol, "protocol cannot be null");

        return new ModFieldInstruction(flag, protocol);

    }

    public static ModFieldInstruction createModField(String protocol, TrafficSelector selector) {
        int flag = Protocol.ProtocolFormatByString(protocol);
        switch(flag){
            case Protocol.MAC:
                checkNotNull(selector, "selector cannot be null");
                Mac_DstCriterion MAC_mac_dst = (Mac_DstCriterion)selector.getCriterion(Criterion.Type.MAC_DST);
                checkNotNull(MAC_mac_dst, "Action ADD_PROTOCOL need MAC_DST field");
                Mac_SrcCriterion MAC_mac_src = (Mac_SrcCriterion)selector.getCriterion(Criterion.Type.MAC_SRC);
                checkNotNull(MAC_mac_src, "Action ADD_PROTOCOL need MAC_SRC field");
                return new ModFieldInstruction(flag, new Mac_Protocol(MAC_mac_dst, MAC_mac_src));
            case Protocol.VLAN1:
                checkNotNull(selector, "selector cannot be null");
                Vlan1_TpidCriterion VLAN1_vlan1_tpid = (Vlan1_TpidCriterion)selector.getCriterion(Criterion.Type.VLAN1_TPID);
                checkNotNull(VLAN1_vlan1_tpid, "Action ADD_PROTOCOL need VLAN1_TPID field");
                Vlan1_QidCriterion VLAN1_vlan1_qid = (Vlan1_QidCriterion)selector.getCriterion(Criterion.Type.VLAN1_QID);
                checkNotNull(VLAN1_vlan1_qid, "Action ADD_PROTOCOL need VLAN1_QID field");
                return new ModFieldInstruction(flag, new Vlan1_Protocol(VLAN1_vlan1_tpid, VLAN1_vlan1_qid));
            case Protocol.VLAN2:
                checkNotNull(selector, "selector cannot be null");
                Vlan2_TpidCriterion VLAN2_vlan2_tpid = (Vlan2_TpidCriterion)selector.getCriterion(Criterion.Type.VLAN2_TPID);
                checkNotNull(VLAN2_vlan2_tpid, "Action ADD_PROTOCOL need VLAN2_TPID field");
                Vlan2_QidCriterion VLAN2_vlan2_qid = (Vlan2_QidCriterion)selector.getCriterion(Criterion.Type.VLAN2_QID);
                checkNotNull(VLAN2_vlan2_qid, "Action ADD_PROTOCOL need VLAN2_QID field");
                return new ModFieldInstruction(flag, new Vlan2_Protocol(VLAN2_vlan2_tpid, VLAN2_vlan2_qid));
            case Protocol.DL:
                checkNotNull(selector, "selector cannot be null");
                Dl_TypeCriterion DL_dl_type = (Dl_TypeCriterion)selector.getCriterion(Criterion.Type.DL_TYPE);
                checkNotNull(DL_dl_type, "Action ADD_PROTOCOL need DL_TYPE field");
                return new ModFieldInstruction(flag, new Dl_Protocol(DL_dl_type));
            case Protocol.IPV4_E:
                checkNotNull(selector, "selector cannot be null");
                Ver_Hl_ECriterion IPV4_E_ver_hl_e = (Ver_Hl_ECriterion)selector.getCriterion(Criterion.Type.VER_HL_E);
                checkNotNull(IPV4_E_ver_hl_e, "Action ADD_PROTOCOL need VER_HL_E field");
                Tos_ECriterion IPV4_E_tos_e = (Tos_ECriterion)selector.getCriterion(Criterion.Type.TOS_E);
                checkNotNull(IPV4_E_tos_e, "Action ADD_PROTOCOL need TOS_E field");
                Tot_Len_ECriterion IPV4_E_tot_len_e = (Tot_Len_ECriterion)selector.getCriterion(Criterion.Type.TOT_LEN_E);
                checkNotNull(IPV4_E_tot_len_e, "Action ADD_PROTOCOL need TOT_LEN_E field");
                Ip_Id_ECriterion IPV4_E_ip_id_e = (Ip_Id_ECriterion)selector.getCriterion(Criterion.Type.IP_ID_E);
                checkNotNull(IPV4_E_ip_id_e, "Action ADD_PROTOCOL need IP_ID_E field");
                Frag_Off_ECriterion IPV4_E_frag_off_e = (Frag_Off_ECriterion)selector.getCriterion(Criterion.Type.FRAG_OFF_E);
                checkNotNull(IPV4_E_frag_off_e, "Action ADD_PROTOCOL need FRAG_OFF_E field");
                Ttl_ECriterion IPV4_E_ttl_e = (Ttl_ECriterion)selector.getCriterion(Criterion.Type.TTL_E);
                checkNotNull(IPV4_E_ttl_e, "Action ADD_PROTOCOL need TTL_E field");
                Ipv4_E_TypeCriterion IPV4_E_ipv4_e_type = (Ipv4_E_TypeCriterion)selector.getCriterion(Criterion.Type.IPV4_E_TYPE);
                checkNotNull(IPV4_E_ipv4_e_type, "Action ADD_PROTOCOL need IPV4_E_TYPE field");
                Ip_Check_ECriterion IPV4_E_ip_check_e = (Ip_Check_ECriterion)selector.getCriterion(Criterion.Type.IP_CHECK_E);
                checkNotNull(IPV4_E_ip_check_e, "Action ADD_PROTOCOL need IP_CHECK_E field");
                Ip_Saddr_ECriterion IPV4_E_ip_saddr_e = (Ip_Saddr_ECriterion)selector.getCriterion(Criterion.Type.IP_SADDR_E);
                checkNotNull(IPV4_E_ip_saddr_e, "Action ADD_PROTOCOL need IP_SADDR_E field");
                Ip_Daddr_ECriterion IPV4_E_ip_daddr_e = (Ip_Daddr_ECriterion)selector.getCriterion(Criterion.Type.IP_DADDR_E);
                checkNotNull(IPV4_E_ip_daddr_e, "Action ADD_PROTOCOL need IP_DADDR_E field");
                return new ModFieldInstruction(flag, new Ipv4_E_Protocol(IPV4_E_ver_hl_e, IPV4_E_tos_e, IPV4_E_tot_len_e, IPV4_E_ip_id_e, IPV4_E_frag_off_e, IPV4_E_ttl_e, IPV4_E_ipv4_e_type, IPV4_E_ip_check_e, IPV4_E_ip_saddr_e, IPV4_E_ip_daddr_e));
            case Protocol.IPV6_E:
                checkNotNull(selector, "selector cannot be null");
                Ipv6_Ver_Tp_Flb_ECriterion IPV6_E_ipv6_ver_tp_flb_e = (Ipv6_Ver_Tp_Flb_ECriterion)selector.getCriterion(Criterion.Type.IPV6_VER_TP_FLB_E);
                checkNotNull(IPV6_E_ipv6_ver_tp_flb_e, "Action ADD_PROTOCOL need IPV6_VER_TP_FLB_E field");
                Ipv6_Plen_ECriterion IPV6_E_ipv6_plen_e = (Ipv6_Plen_ECriterion)selector.getCriterion(Criterion.Type.IPV6_PLEN_E);
                checkNotNull(IPV6_E_ipv6_plen_e, "Action ADD_PROTOCOL need IPV6_PLEN_E field");
                Ipv6_E_TypeCriterion IPV6_E_ipv6_e_type = (Ipv6_E_TypeCriterion)selector.getCriterion(Criterion.Type.IPV6_E_TYPE);
                checkNotNull(IPV6_E_ipv6_e_type, "Action ADD_PROTOCOL need IPV6_E_TYPE field");
                Ipv6_Hlmt_ECriterion IPV6_E_ipv6_hlmt_e = (Ipv6_Hlmt_ECriterion)selector.getCriterion(Criterion.Type.IPV6_HLMT_E);
                checkNotNull(IPV6_E_ipv6_hlmt_e, "Action ADD_PROTOCOL need IPV6_HLMT_E field");
                Ipv6_Src_ECriterion IPV6_E_ipv6_src_e = (Ipv6_Src_ECriterion)selector.getCriterion(Criterion.Type.IPV6_SRC_E);
                checkNotNull(IPV6_E_ipv6_src_e, "Action ADD_PROTOCOL need IPV6_SRC_E field");
                Ipv6_Dst_ECriterion IPV6_E_ipv6_dst_e = (Ipv6_Dst_ECriterion)selector.getCriterion(Criterion.Type.IPV6_DST_E);
                checkNotNull(IPV6_E_ipv6_dst_e, "Action ADD_PROTOCOL need IPV6_DST_E field");
                return new ModFieldInstruction(flag, new Ipv6_E_Protocol(IPV6_E_ipv6_ver_tp_flb_e, IPV6_E_ipv6_plen_e, IPV6_E_ipv6_e_type, IPV6_E_ipv6_hlmt_e, IPV6_E_ipv6_src_e, IPV6_E_ipv6_dst_e));
            case Protocol.UDP:
                checkNotNull(selector, "selector cannot be null");
                Udp_SourceCriterion UDP_udp_source = (Udp_SourceCriterion)selector.getCriterion(Criterion.Type.UDP_SOURCE);
                checkNotNull(UDP_udp_source, "Action ADD_PROTOCOL need UDP_SOURCE field");
                Udp_DestCriterion UDP_udp_dest = (Udp_DestCriterion)selector.getCriterion(Criterion.Type.UDP_DEST);
                checkNotNull(UDP_udp_dest, "Action ADD_PROTOCOL need UDP_DEST field");
                LenCriterion UDP_len = (LenCriterion)selector.getCriterion(Criterion.Type.LEN);
                checkNotNull(UDP_len, "Action ADD_PROTOCOL need LEN field");
                Udp_CheckCriterion UDP_udp_check = (Udp_CheckCriterion)selector.getCriterion(Criterion.Type.UDP_CHECK);
                checkNotNull(UDP_udp_check, "Action ADD_PROTOCOL need UDP_CHECK field");
                return new ModFieldInstruction(flag, new Udp_Protocol(UDP_udp_source, UDP_udp_dest, UDP_len, UDP_udp_check));
            case Protocol.SRV6_1:
                checkNotNull(selector, "selector cannot be null");
                Srv6_TypeCriterion SRV6_1_srv6_type = (Srv6_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_TYPE);
                checkNotNull(SRV6_1_srv6_type, "Action ADD_PROTOCOL need SRV6_TYPE field");
                Srv6_Hdr_Ext_LenCriterion SRV6_1_srv6_hdr_ext_len = (Srv6_Hdr_Ext_LenCriterion)selector.getCriterion(Criterion.Type.SRV6_HDR_EXT_LEN);
                checkNotNull(SRV6_1_srv6_hdr_ext_len, "Action ADD_PROTOCOL need SRV6_HDR_EXT_LEN field");
                Srv6_Routing_TypeCriterion SRV6_1_srv6_routing_Type = (Srv6_Routing_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_ROUTING_TYPE);
                checkNotNull(SRV6_1_srv6_routing_Type, "Action ADD_PROTOCOL need SRV6_ROUTING_TYPE field");
                Srv6_Segments_LeftCriterion SRV6_1_srv6_segments_left = (Srv6_Segments_LeftCriterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTS_LEFT);
                checkNotNull(SRV6_1_srv6_segments_left, "Action ADD_PROTOCOL need SRV6_SEGMENTS_LEFT field");
                Srv6_Last_EntyCriterion SRV6_1_srv6_last_enty = (Srv6_Last_EntyCriterion)selector.getCriterion(Criterion.Type.SRV6_LAST_ENTY);
                checkNotNull(SRV6_1_srv6_last_enty, "Action ADD_PROTOCOL need SRV6_LAST_ENTY field");
                Srv6_FlagsCriterion SRV6_1_srv6_flags = (Srv6_FlagsCriterion)selector.getCriterion(Criterion.Type.SRV6_FLAGS);
                checkNotNull(SRV6_1_srv6_flags, "Action ADD_PROTOCOL need SRV6_FLAGS field");
                Srv6_TagCriterion SRV6_1_srv6_tag = (Srv6_TagCriterion)selector.getCriterion(Criterion.Type.SRV6_TAG);
                checkNotNull(SRV6_1_srv6_tag, "Action ADD_PROTOCOL need SRV6_TAG field");
                Srv6_Segmentlist1Criterion SRV6_1_srv6_segmentlist1 = (Srv6_Segmentlist1Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST1);
                checkNotNull(SRV6_1_srv6_segmentlist1, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST1 field");
                return new ModFieldInstruction(flag, new Srv6_1_Protocol(SRV6_1_srv6_type, SRV6_1_srv6_hdr_ext_len, SRV6_1_srv6_routing_Type, SRV6_1_srv6_segments_left, SRV6_1_srv6_last_enty, SRV6_1_srv6_flags, SRV6_1_srv6_tag, SRV6_1_srv6_segmentlist1));
            case Protocol.SRV6_2:
                checkNotNull(selector, "selector cannot be null");
                Srv6_TypeCriterion SRV6_2_srv6_type = (Srv6_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_TYPE);
                checkNotNull(SRV6_2_srv6_type, "Action ADD_PROTOCOL need SRV6_TYPE field");
                Srv6_Hdr_Ext_LenCriterion SRV6_2_srv6_hdr_ext_len = (Srv6_Hdr_Ext_LenCriterion)selector.getCriterion(Criterion.Type.SRV6_HDR_EXT_LEN);
                checkNotNull(SRV6_2_srv6_hdr_ext_len, "Action ADD_PROTOCOL need SRV6_HDR_EXT_LEN field");
                Srv6_Routing_TypeCriterion SRV6_2_srv6_routing_Type = (Srv6_Routing_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_ROUTING_TYPE);
                checkNotNull(SRV6_2_srv6_routing_Type, "Action ADD_PROTOCOL need SRV6_ROUTING_TYPE field");
                Srv6_Segments_LeftCriterion SRV6_2_srv6_segments_left = (Srv6_Segments_LeftCriterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTS_LEFT);
                checkNotNull(SRV6_2_srv6_segments_left, "Action ADD_PROTOCOL need SRV6_SEGMENTS_LEFT field");
                Srv6_Last_EntyCriterion SRV6_2_srv6_last_enty = (Srv6_Last_EntyCriterion)selector.getCriterion(Criterion.Type.SRV6_LAST_ENTY);
                checkNotNull(SRV6_2_srv6_last_enty, "Action ADD_PROTOCOL need SRV6_LAST_ENTY field");
                Srv6_FlagsCriterion SRV6_2_srv6_flags = (Srv6_FlagsCriterion)selector.getCriterion(Criterion.Type.SRV6_FLAGS);
                checkNotNull(SRV6_2_srv6_flags, "Action ADD_PROTOCOL need SRV6_FLAGS field");
                Srv6_TagCriterion SRV6_2_srv6_tag = (Srv6_TagCriterion)selector.getCriterion(Criterion.Type.SRV6_TAG);
                checkNotNull(SRV6_2_srv6_tag, "Action ADD_PROTOCOL need SRV6_TAG field");
                Srv6_Segmentlist1Criterion SRV6_2_srv6_segmentlist1 = (Srv6_Segmentlist1Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST1);
                checkNotNull(SRV6_2_srv6_segmentlist1, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST1 field");
                Srv6_Segmentlist2Criterion SRV6_2_srv6_segmentlist2 = (Srv6_Segmentlist2Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST2);
                checkNotNull(SRV6_2_srv6_segmentlist2, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST2 field");
                return new ModFieldInstruction(flag, new Srv6_2_Protocol(SRV6_2_srv6_type, SRV6_2_srv6_hdr_ext_len, SRV6_2_srv6_routing_Type, SRV6_2_srv6_segments_left, SRV6_2_srv6_last_enty, SRV6_2_srv6_flags, SRV6_2_srv6_tag, SRV6_2_srv6_segmentlist1, SRV6_2_srv6_segmentlist2));
            case Protocol.SRV6_3:
                checkNotNull(selector, "selector cannot be null");
                Srv6_TypeCriterion SRV6_3_srv6_type = (Srv6_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_TYPE);
                checkNotNull(SRV6_3_srv6_type, "Action ADD_PROTOCOL need SRV6_TYPE field");
                Srv6_Hdr_Ext_LenCriterion SRV6_3_srv6_hdr_ext_len = (Srv6_Hdr_Ext_LenCriterion)selector.getCriterion(Criterion.Type.SRV6_HDR_EXT_LEN);
                checkNotNull(SRV6_3_srv6_hdr_ext_len, "Action ADD_PROTOCOL need SRV6_HDR_EXT_LEN field");
                Srv6_Routing_TypeCriterion SRV6_3_srv6_routing_Type = (Srv6_Routing_TypeCriterion)selector.getCriterion(Criterion.Type.SRV6_ROUTING_TYPE);
                checkNotNull(SRV6_3_srv6_routing_Type, "Action ADD_PROTOCOL need SRV6_ROUTING_TYPE field");
                Srv6_Segments_LeftCriterion SRV6_3_srv6_segments_left = (Srv6_Segments_LeftCriterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTS_LEFT);
                checkNotNull(SRV6_3_srv6_segments_left, "Action ADD_PROTOCOL need SRV6_SEGMENTS_LEFT field");
                Srv6_Last_EntyCriterion SRV6_3_srv6_last_enty = (Srv6_Last_EntyCriterion)selector.getCriterion(Criterion.Type.SRV6_LAST_ENTY);
                checkNotNull(SRV6_3_srv6_last_enty, "Action ADD_PROTOCOL need SRV6_LAST_ENTY field");
                Srv6_FlagsCriterion SRV6_3_srv6_flags = (Srv6_FlagsCriterion)selector.getCriterion(Criterion.Type.SRV6_FLAGS);
                checkNotNull(SRV6_3_srv6_flags, "Action ADD_PROTOCOL need SRV6_FLAGS field");
                Srv6_TagCriterion SRV6_3_srv6_tag = (Srv6_TagCriterion)selector.getCriterion(Criterion.Type.SRV6_TAG);
                checkNotNull(SRV6_3_srv6_tag, "Action ADD_PROTOCOL need SRV6_TAG field");
                Srv6_Segmentlist1Criterion SRV6_3_srv6_segmentlist1 = (Srv6_Segmentlist1Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST1);
                checkNotNull(SRV6_3_srv6_segmentlist1, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST1 field");
                Srv6_Segmentlist2Criterion SRV6_3_srv6_segmentlist2 = (Srv6_Segmentlist2Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST2);
                checkNotNull(SRV6_3_srv6_segmentlist2, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST2 field");
                Srv6_Segmentlist3Criterion SRV6_3_srv6_segmentlist3 = (Srv6_Segmentlist3Criterion)selector.getCriterion(Criterion.Type.SRV6_SEGMENTLIST3);
                checkNotNull(SRV6_3_srv6_segmentlist3, "Action ADD_PROTOCOL need SRV6_SEGMENTLIST3 field");
                return new ModFieldInstruction(flag, new Srv6_3_Protocol(SRV6_3_srv6_type, SRV6_3_srv6_hdr_ext_len, SRV6_3_srv6_routing_Type, SRV6_3_srv6_segments_left, SRV6_3_srv6_last_enty, SRV6_3_srv6_flags, SRV6_3_srv6_tag, SRV6_3_srv6_segmentlist1, SRV6_3_srv6_segmentlist2, SRV6_3_srv6_segmentlist3));
            case Protocol.IPV6_I:
                checkNotNull(selector, "selector cannot be null");
                Ipv6_Ver_Tp_Flb_ICriterion IPV6_I_ipv6_ver_tp_flb_i = (Ipv6_Ver_Tp_Flb_ICriterion)selector.getCriterion(Criterion.Type.IPV6_VER_TP_FLB_I);
                checkNotNull(IPV6_I_ipv6_ver_tp_flb_i, "Action ADD_PROTOCOL need IPV6_VER_TP_FLB_I field");
                Ipv6_Plen_ICriterion IPV6_I_ipv6_plen_i = (Ipv6_Plen_ICriterion)selector.getCriterion(Criterion.Type.IPV6_PLEN_I);
                checkNotNull(IPV6_I_ipv6_plen_i, "Action ADD_PROTOCOL need IPV6_PLEN_I field");
                Ipv6_I_TypeCriterion IPV6_I_ipv6_i_type = (Ipv6_I_TypeCriterion)selector.getCriterion(Criterion.Type.IPV6_I_TYPE);
                checkNotNull(IPV6_I_ipv6_i_type, "Action ADD_PROTOCOL need IPV6_I_TYPE field");
                Ipv6_Hlmt_ICriterion IPV6_I_ipv6_hlmt_i = (Ipv6_Hlmt_ICriterion)selector.getCriterion(Criterion.Type.IPV6_HLMT_I);
                checkNotNull(IPV6_I_ipv6_hlmt_i, "Action ADD_PROTOCOL need IPV6_HLMT_I field");
                Ipv6_Src_ICriterion IPV6_I_ipv6_src_i = (Ipv6_Src_ICriterion)selector.getCriterion(Criterion.Type.IPV6_SRC_I);
                checkNotNull(IPV6_I_ipv6_src_i, "Action ADD_PROTOCOL need IPV6_SRC_I field");
                Ipv6_Dst_ICriterion IPV6_I_ipv6_dst_i = (Ipv6_Dst_ICriterion)selector.getCriterion(Criterion.Type.IPV6_DST_I);
                checkNotNull(IPV6_I_ipv6_dst_i, "Action ADD_PROTOCOL need IPV6_DST_I field");
                return new ModFieldInstruction(flag, new Ipv6_I_Protocol(IPV6_I_ipv6_ver_tp_flb_i, IPV6_I_ipv6_plen_i, IPV6_I_ipv6_i_type, IPV6_I_ipv6_hlmt_i, IPV6_I_ipv6_src_i, IPV6_I_ipv6_dst_i));
            default:
                throw new UnsupportedOperationException("Action ADD_PROTOCOL add a unsupported protocol");
        }

    }


    public static class ModFieldInstruction implements Instruction {
        private final int flag;
        private final Protocol protocol;

        ModFieldInstruction(int flag, Protocol protocol) {
            this.flag = flag;
            this.protocol = protocol;
        }
        
        public static ModFieldInstruction readFrom(ByteBuf bb){
            int start = bb.readerIndex();
        
            byte type = bb.readByte();
            byte raw = bb.readByte();
            short len = bb.readShort();
            int protocol_type = bb.readInt();
        
            int protocolLength = bb.readerIndex();
            Protocol result = null;
            switch(protocol_type){
                case Protocol.MAC:
                    result = Mac_Protocol.read(bb);
                    break;
                case Protocol.VLAN1:
                    result = Vlan1_Protocol.read(bb);
                    break;
                case Protocol.VLAN2:
                    result = Vlan2_Protocol.read(bb);
                    break;
                case Protocol.DL:
                    result = Dl_Protocol.read(bb);
                    break;
                case Protocol.IPV4_E:
                    result = Ipv4_E_Protocol.read(bb);
                    break;
                case Protocol.IPV6_E:
                    result = Ipv6_E_Protocol.read(bb);
                    break;
                case Protocol.UDP:
                    result = Udp_Protocol.read(bb);
                    break;
                case Protocol.SRV6_1:
                    result = Srv6_1_Protocol.read(bb);
                    break;
                case Protocol.SRV6_2:
                    result = Srv6_2_Protocol.read(bb);
                    break;
                case Protocol.SRV6_3:
                    result = Srv6_3_Protocol.read(bb);
                    break;
                case Protocol.IPV6_I:
                    result = Ipv6_I_Protocol.read(bb);
                    break;
               default:
                    throw new UnsupportedOperationException("Action ADD_PROTOCOL add a unsupported protocol");
            }
            bb.skipBytes(bb.readerIndex() - protocolLength); 
        
            int pad = 8 - ((bb.readerIndex() - start) % 8);
            bb.skipBytes(pad); 
        
            return createModField(protocol_type, result);
        }
        
        @Override
        public void write(ByteBuf bb){
            int start = bb.writerIndex();
            // type 
            bb.writeByte((byte)61);
            // raw
            bb.writeByte(0xff);
            // len
            int lengthIndex = bb.writerIndex();
            bb.writeShort((short)0);
            // flag
            bb.writeInt(Integer.reverseBytes(flag));
            // protocol
            protocol.write(bb);
            // mask
            protocol.writeMask(bb);
            //pad
            int pad = 8 - ((bb.writerIndex() - start) % 8);
            bb.writeZero(pad);
        
            int length = bb.writerIndex() - start;
            bb.setShort(lengthIndex, Short.reverseBytes((short)length));
        }
        
        @Override
        public Type type() {
            return Type.MOD_FIELD;
        }
        
        @Override
        public String toString() {
            return "ModField[" + protocol.toString() + "]";
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(type().ordinal(), flag);
        }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof ModFieldInstruction) {
                ModFieldInstruction that = (ModFieldInstruction) obj;
                return Objects.equals(flag, that.flag) && Objects.equals(protocol, that.protocol);
        
            }
            return false;
        }

    }
}
