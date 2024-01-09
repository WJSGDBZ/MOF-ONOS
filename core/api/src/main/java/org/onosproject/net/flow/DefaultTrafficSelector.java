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
package org.onosproject.net.flow;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.ExtensionCriterion;
import org.onosproject.net.flow.criteria.ExtensionSelector;
import org.onosproject.net.flow.criteria.ExtensionSelectorType;
import org.onosproject.net.flow.criteria.PiCriterion;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import javax.sound.sampled.AudioFileFormat.Type;

import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.onosproject.net.flow.criteria.Criterion.Type.EXTENSION;
import org.onosproject.net.flow.criteria.PortCriterion;

import org.onosproject.net.flow.criteria.Mac_DstCriterion;
import org.onlab.packet.Mac_Dst;
import org.onosproject.net.flow.criteria.Mac_SrcCriterion;
import org.onlab.packet.Mac_Src;
import org.onosproject.net.flow.criteria.Vlan1_TpidCriterion;
import org.onosproject.net.flow.criteria.Vlan1_QidCriterion;
import org.onosproject.net.flow.criteria.Vlan2_TpidCriterion;
import org.onosproject.net.flow.criteria.Vlan2_QidCriterion;
import org.onosproject.net.flow.criteria.Dl_TypeCriterion;
import org.onosproject.net.flow.criteria.Ver_Hl_ECriterion;
import org.onosproject.net.flow.criteria.Tos_ECriterion;
import org.onosproject.net.flow.criteria.Tot_Len_ECriterion;
import org.onosproject.net.flow.criteria.Ip_Id_ECriterion;
import org.onosproject.net.flow.criteria.Frag_Off_ECriterion;
import org.onosproject.net.flow.criteria.Ttl_ECriterion;
import org.onosproject.net.flow.criteria.Ipv4_E_TypeCriterion;
import org.onosproject.net.flow.criteria.Ip_Check_ECriterion;
import org.onosproject.net.flow.criteria.Ip_Saddr_ECriterion;
import org.onosproject.net.flow.criteria.Ip_Daddr_ECriterion;
import org.onosproject.net.flow.criteria.Ipv6_Ver_Tp_Flb_ECriterion;
import org.onosproject.net.flow.criteria.Ipv6_Plen_ECriterion;
import org.onosproject.net.flow.criteria.Ipv6_E_TypeCriterion;
import org.onosproject.net.flow.criteria.Ipv6_Hlmt_ECriterion;
import org.onosproject.net.flow.criteria.Ipv6_Src_ECriterion;
import org.onlab.packet.Ipv6_Src_E;
import org.onosproject.net.flow.criteria.Ipv6_Dst_ECriterion;
import org.onlab.packet.Ipv6_Dst_E;
import org.onosproject.net.flow.criteria.Tcp_SourceCriterion;
import org.onosproject.net.flow.criteria.Tcp_DestCriterion;
import org.onosproject.net.flow.criteria.SeqCriterion;
import org.onosproject.net.flow.criteria.Ack_SeqCriterion;
import org.onosproject.net.flow.criteria.Off_BitsCriterion;
import org.onosproject.net.flow.criteria.WindowCriterion;
import org.onosproject.net.flow.criteria.Tcp_CheckCriterion;
import org.onosproject.net.flow.criteria.Urg_PtrCriterion;
import org.onosproject.net.flow.criteria.Udp_SourceCriterion;
import org.onosproject.net.flow.criteria.Udp_DestCriterion;
import org.onosproject.net.flow.criteria.LenCriterion;
import org.onosproject.net.flow.criteria.Udp_CheckCriterion;
import org.onosproject.net.flow.criteria.Srv6_TypeCriterion;
import org.onosproject.net.flow.criteria.Srv6_Hdr_Ext_LenCriterion;
import org.onosproject.net.flow.criteria.Srv6_Routing_TypeCriterion;
import org.onosproject.net.flow.criteria.Srv6_Segments_LeftCriterion;
import org.onosproject.net.flow.criteria.Srv6_Last_EntyCriterion;
import org.onosproject.net.flow.criteria.Srv6_FlagsCriterion;
import org.onosproject.net.flow.criteria.Srv6_TagCriterion;
import org.onosproject.net.flow.criteria.Srv6_Segmentlist1Criterion;
import org.onlab.packet.Srv6_Segmentlist1;
import org.onosproject.net.flow.criteria.Srv6_Segmentlist2Criterion;
import org.onlab.packet.Srv6_Segmentlist2;
import org.onosproject.net.flow.criteria.Srv6_Segmentlist3Criterion;
import org.onlab.packet.Srv6_Segmentlist3;
import org.onosproject.net.flow.criteria.Ipv6_Ver_Tp_Flb_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Plen_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_I_TypeCriterion;
import org.onosproject.net.flow.criteria.Ipv6_Hlmt_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Src_ICriterion;
import org.onlab.packet.Ipv6_Src_I;
import org.onosproject.net.flow.criteria.Ipv6_Dst_ICriterion;
import org.onlab.packet.Ipv6_Dst_I;
import org.onosproject.net.flow.criteria.Ver_Hl_ICriterion;
import org.onosproject.net.flow.criteria.Tos_ICriterion;
import org.onosproject.net.flow.criteria.Tot_Len_ICriterion;
import org.onosproject.net.flow.criteria.Ip_Id_ICriterion;
import org.onosproject.net.flow.criteria.Frag_Off_ICriterion;
import org.onosproject.net.flow.criteria.Ttl_ICriterion;
import org.onosproject.net.flow.criteria.Ipv4_I_TypeCriterion;
import org.onosproject.net.flow.criteria.Ip_Check_ICriterion;
import org.onosproject.net.flow.criteria.Ip_Saddr_ICriterion;
import org.onosproject.net.flow.criteria.Ip_Daddr_ICriterion;
/**
 * Default traffic selector implementation.
 */
public final class DefaultTrafficSelector implements TrafficSelector {
    private final Logger log = getLogger(DefaultTrafficSelector.class);
    private static final Comparator<? super Criterion> TYPE_COMPARATOR = (c1, c2) -> {
        if (c1.type() == EXTENSION && c2.type() == EXTENSION) {
            return ((ExtensionCriterion) c1).extensionSelector().type().toInt()
                    - ((ExtensionCriterion) c2).extensionSelector().type().toInt();
        } else {
            return c1.type().compareTo(c2.type());
        }
    };

    private final Set<Criterion> criteria;

    private final HashMap<Criterion.Type, Criterion> match;

    private static final DefaultTrafficSelector EMPTY = new DefaultTrafficSelector(Collections.emptySet(),
            Collections.emptySet());

    /**
     * Creates a new traffic selector with the specified criteria.
     *
     * @param criteria    criteria
     * @param extCriteria extension criteria
     */
    private DefaultTrafficSelector(Collection<Criterion> criteria, Collection<Criterion> extCriteria) {
        // log.info("DefaultTrafficSelector start to build");
        this.match = new HashMap<>();
        TreeSet<Criterion> elements = new TreeSet<>(TYPE_COMPARATOR);
        elements.addAll(criteria);
        elements.addAll(extCriteria);
        this.criteria = ImmutableSet.copyOf(elements);
    }

    private DefaultTrafficSelector(Collection<Criterion> criteria, Collection<Criterion> extCriteria,
            HashMap<Criterion.Type, Criterion> match) {
        // log.info("DefaultTrafficSelector start to build");
        this.match = match;
        TreeSet<Criterion> elements = new TreeSet<>(TYPE_COMPARATOR);
        elements.addAll(criteria);
        elements.addAll(extCriteria);
        this.criteria = ImmutableSet.copyOf(elements);
    }

    @Override
    public Set<Criterion> criteria() {
        return criteria;
    }

    @Override
    public Criterion getCriterion(Criterion.Type type) {
        for (Criterion c : criteria) {
            if (c.type() == type) {
                return c;
            }
        }
        return null;
    }

    @Override
    public int hashCode() {
        return criteria.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof DefaultTrafficSelector) {
            DefaultTrafficSelector that = (DefaultTrafficSelector) obj;
            return Objects.equals(criteria, that.criteria);

        }
        return false;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("criteria", criteria)
                .toString();
    }

   /**
     * Returns a new traffic selector builder.
     *
     * @return traffic selector builder
     */
    public static DefaultTrafficSelector.Builder builder() {
        return new Builder();
    }

    /**
     * Returns an empty traffic selector.
     *
     * @return empty traffic selector
     */
    public static DefaultTrafficSelector emptySelector() {
        return EMPTY;
    }

    /**
     * Returns a new traffic selector builder primed to produce entities
     * patterned after the supplied selector.
     *
     * @param selector base selector
     * @return traffic selector builder
     */
    public static DefaultTrafficSelector.Builder builder(TrafficSelector selector) {
        return new Builder(selector);
    }

    /**
     * Builder of traffic selector entities.
     */
    public static final class Builder implements TrafficSelector.Builder {

        private final Map<Criterion.Type, Criterion> selector = new HashMap<>();
        private final Map<ExtensionSelectorType, Criterion> extSelector = new HashMap<>();
        private final HashMap<Criterion.Type, Criterion> match = new HashMap<>();

        private Builder() {
        }

        private Builder(TrafficSelector selector) {
            for (Criterion c : selector.criteria()) {
                add(c);
            }
        }

        @Override
        public Builder add(Criterion criterion) {
            if (criterion.type() == EXTENSION) {
                extSelector.put(((ExtensionCriterion) criterion).extensionSelector().type(), criterion);
            } else {
                selector.put(criterion.type(), criterion);
                match.put(criterion.type(), criterion);
            }
            return this;
        }

        @Override
        public Builder matchInPort(PortNumber port) {
            return add(Criteria.matchInPort(port));
        }

        @Override
        public Builder matchInPhyPort(PortNumber port) {
            return add(Criteria.matchInPhyPort(port));
        }

        @Override
        public Builder matchMetadata(long metadata) {
            return add(Criteria.matchMetadata(metadata));
        }

        @Override
        public Builder matchEthDst(MacAddress addr) {
            return add(Criteria.matchEthDst(addr));
        }

        @Override
        public Builder matchEthDstMasked(MacAddress addr, MacAddress mask) {
            return add(Criteria.matchEthDstMasked(addr, mask));
        }

        @Override
        public Builder matchEthSrc(MacAddress addr) {
            return add(Criteria.matchEthSrc(addr));
        }

        @Override
        public Builder matchEthSrcMasked(MacAddress addr, MacAddress mask) {
            return add(Criteria.matchEthSrcMasked(addr, mask));
        }

        @Override
        public Builder matchEthType(short ethType) {
            return add(Criteria.matchEthType(ethType));
        }

        @Override
        public Builder matchVlanId(VlanId vlanId) {
            return add(Criteria.matchVlanId(vlanId));
        }

        @Override
        public Builder matchVlanPcp(byte vlanPcp) {
            return add(Criteria.matchVlanPcp(vlanPcp));
        }

        @Override
        public Builder matchInnerVlanId(VlanId vlanId) {
            return add(Criteria.matchInnerVlanId(vlanId));
        }

        @Override
        public Builder matchInnerVlanPcp(byte vlanPcp) {
            return add(Criteria.matchInnerVlanPcp(vlanPcp));
        }

        @Override
        public Builder matchIPDscp(byte ipDscp) {
            return add(Criteria.matchIPDscp(ipDscp));
        }

        @Override
        public Builder matchIPEcn(byte ipEcn) {
            return add(Criteria.matchIPEcn(ipEcn));
        }

        @Override
        public Builder matchIPProtocol(byte proto) {
            return add(Criteria.matchIPProtocol(proto));
        }

        @Override
        public Builder matchIPSrc(IpPrefix ip) {
            return add(Criteria.matchIPSrc(ip));
        }

        @Override
        public Builder matchIPDst(IpPrefix ip) {
            return add(Criteria.matchIPDst(ip));
        }

        @Override
        public Builder matchTcpSrc(TpPort tcpPort) {
            return add(Criteria.matchTcpSrc(tcpPort));
        }

        @Override
        public TrafficSelector.Builder matchTcpSrcMasked(TpPort tcpPort, TpPort mask) {
            return add(Criteria.matchTcpSrcMasked(tcpPort, mask));
        }

        @Override
        public Builder matchTcpDst(TpPort tcpPort) {
            return add(Criteria.matchTcpDst(tcpPort));
        }

        @Override
        public TrafficSelector.Builder matchTcpDstMasked(TpPort tcpPort, TpPort mask) {
            return add(Criteria.matchTcpDstMasked(tcpPort, mask));
        }

        @Override
        public Builder matchUdpSrc(TpPort udpPort) {
            return add(Criteria.matchUdpSrc(udpPort));
        }

        @Override
        public TrafficSelector.Builder matchUdpSrcMasked(TpPort udpPort, TpPort mask) {
            return add(Criteria.matchUdpSrcMasked(udpPort, mask));
        }

        @Override
        public Builder matchUdpDst(TpPort udpPort) {
            return add(Criteria.matchUdpDst(udpPort));
        }

        @Override
        public TrafficSelector.Builder matchUdpDstMasked(TpPort udpPort, TpPort mask) {
            return add(Criteria.matchUdpDstMasked(udpPort, mask));
        }

        @Override
        public Builder matchSctpSrc(TpPort sctpPort) {
            return add(Criteria.matchSctpSrc(sctpPort));
        }

        @Override
        public TrafficSelector.Builder matchSctpSrcMasked(TpPort sctpPort, TpPort mask) {
            return add(Criteria.matchSctpSrcMasked(sctpPort, mask));
        }

        @Override
        public Builder matchSctpDst(TpPort sctpPort) {
            return add(Criteria.matchSctpDst(sctpPort));
        }

        @Override
        public TrafficSelector.Builder matchSctpDstMasked(TpPort sctpPort, TpPort mask) {
            return add(Criteria.matchSctpDstMasked(sctpPort, mask));
        }

        @Override
        public Builder matchIcmpType(byte icmpType) {
            return add(Criteria.matchIcmpType(icmpType));
        }

        @Override
        public Builder matchIcmpCode(byte icmpCode) {
            return add(Criteria.matchIcmpCode(icmpCode));
        }

        @Override
        public Builder matchIPv6Src(IpPrefix ip) {
            return add(Criteria.matchIPv6Src(ip));
        }

        @Override
        public Builder matchIPv6Dst(IpPrefix ip) {
            return add(Criteria.matchIPv6Dst(ip));
        }

        @Override
        public Builder matchIPv6FlowLabel(int flowLabel) {
            return add(Criteria.matchIPv6FlowLabel(flowLabel));
        }

        @Override
        public Builder matchIcmpv6Type(byte icmpv6Type) {
            return add(Criteria.matchIcmpv6Type(icmpv6Type));
        }

        @Override
        public Builder matchIcmpv6Code(byte icmpv6Code) {
            return add(Criteria.matchIcmpv6Code(icmpv6Code));
        }

        @Override
        public Builder matchIPv6NDTargetAddress(Ip6Address targetAddress) {
            return add(Criteria.matchIPv6NDTargetAddress(targetAddress));
        }

        @Override
        public Builder matchIPv6NDSourceLinkLayerAddress(MacAddress mac) {
            return add(Criteria.matchIPv6NDSourceLinkLayerAddress(mac));
        }

        @Override
        public Builder matchIPv6NDTargetLinkLayerAddress(MacAddress mac) {
            return add(Criteria.matchIPv6NDTargetLinkLayerAddress(mac));
        }

        @Override
        public Builder matchMplsLabel(MplsLabel mplsLabel) {
            return add(Criteria.matchMplsLabel(mplsLabel));
        }

        @Override
        public Builder matchMplsBos(boolean mplsBos) {
            return add(Criteria.matchMplsBos(mplsBos));
        }

        @Override
        public TrafficSelector.Builder matchTunnelId(long tunnelId) {
            return add(Criteria.matchTunnelId(tunnelId));
        }

        @Override
        public Builder matchIPv6ExthdrFlags(short exthdrFlags) {
            return add(Criteria.matchIPv6ExthdrFlags(exthdrFlags));
        }

        @Override
        public Builder matchArpTpa(Ip4Address addr) {
            return add(Criteria.matchArpTpa(addr));
        }

        @Override
        public Builder matchArpSpa(Ip4Address addr) {
            return add(Criteria.matchArpSpa(addr));
        }

        @Override
        public Builder matchArpTha(MacAddress addr) {
            return add(Criteria.matchArpTha(addr));
        }

        @Override
        public Builder matchArpSha(MacAddress addr) {
            return add(Criteria.matchArpSha(addr));
        }

        @Override
        public Builder matchArpOp(int arpOp) {
            return add(Criteria.matchArpOp(arpOp));
        }

        @Override
        public Builder matchPi(PiCriterion piCriterion) {
            return add(checkNotNull(piCriterion, "Protocol-independent criterion cannot be null"));
        }

        @Override
        public Builder selectInport(int port) {
            return add(Criteria.matchInPort(PortNumber.portNumber(port)));
        }

        @Override
        public Builder selectInport(int port, int mask) {
            return add(Criteria.matchInPort(PortNumber.portNumber(port)));
        }
                @Override
        public Builder selectMac_Dst(Mac_Dst mac_dst) {
            return add(Criteria.selectMac_Dst(mac_dst));
        }
  
        @Override
        public Builder selectMac_Dst(Mac_Dst mac_dst, Mac_Dst mask) {
            return add(Criteria.selectMac_Dst(mac_dst, mask));
        }

        @Override
        public Builder selectMac_Src(Mac_Src mac_src) {
            return add(Criteria.selectMac_Src(mac_src));
        }
  
        @Override
        public Builder selectMac_Src(Mac_Src mac_src, Mac_Src mask) {
            return add(Criteria.selectMac_Src(mac_src, mask));
        }

        @Override
        public Builder selectVlan1_Tpid(long vlan1_tpid) {
            return add(Criteria.selectVlan1_Tpid(vlan1_tpid));
        }
  
        @Override
        public Builder selectVlan1_Tpid(long vlan1_tpid, long mask) {
            return add(Criteria.selectVlan1_Tpid(vlan1_tpid, mask));
        }

        @Override
        public Builder selectVlan1_Qid(long vlan1_qid) {
            return add(Criteria.selectVlan1_Qid(vlan1_qid));
        }
  
        @Override
        public Builder selectVlan1_Qid(long vlan1_qid, long mask) {
            return add(Criteria.selectVlan1_Qid(vlan1_qid, mask));
        }

        @Override
        public Builder selectVlan2_Tpid(long vlan2_tpid) {
            return add(Criteria.selectVlan2_Tpid(vlan2_tpid));
        }
  
        @Override
        public Builder selectVlan2_Tpid(long vlan2_tpid, long mask) {
            return add(Criteria.selectVlan2_Tpid(vlan2_tpid, mask));
        }

        @Override
        public Builder selectVlan2_Qid(long vlan2_qid) {
            return add(Criteria.selectVlan2_Qid(vlan2_qid));
        }
  
        @Override
        public Builder selectVlan2_Qid(long vlan2_qid, long mask) {
            return add(Criteria.selectVlan2_Qid(vlan2_qid, mask));
        }

        @Override
        public Builder selectDl_Type(long dl_type) {
            return add(Criteria.selectDl_Type(dl_type));
        }
  
        @Override
        public Builder selectDl_Type(long dl_type, long mask) {
            return add(Criteria.selectDl_Type(dl_type, mask));
        }

        @Override
        public Builder selectVer_Hl_E(long ver_hl_e) {
            return add(Criteria.selectVer_Hl_E(ver_hl_e));
        }
  
        @Override
        public Builder selectVer_Hl_E(long ver_hl_e, long mask) {
            return add(Criteria.selectVer_Hl_E(ver_hl_e, mask));
        }

        @Override
        public Builder selectTos_E(long tos_e) {
            return add(Criteria.selectTos_E(tos_e));
        }
  
        @Override
        public Builder selectTos_E(long tos_e, long mask) {
            return add(Criteria.selectTos_E(tos_e, mask));
        }

        @Override
        public Builder selectTot_Len_E(long tot_len_e) {
            return add(Criteria.selectTot_Len_E(tot_len_e));
        }
  
        @Override
        public Builder selectTot_Len_E(long tot_len_e, long mask) {
            return add(Criteria.selectTot_Len_E(tot_len_e, mask));
        }

        @Override
        public Builder selectIp_Id_E(long ip_id_e) {
            return add(Criteria.selectIp_Id_E(ip_id_e));
        }
  
        @Override
        public Builder selectIp_Id_E(long ip_id_e, long mask) {
            return add(Criteria.selectIp_Id_E(ip_id_e, mask));
        }

        @Override
        public Builder selectFrag_Off_E(long frag_off_e) {
            return add(Criteria.selectFrag_Off_E(frag_off_e));
        }
  
        @Override
        public Builder selectFrag_Off_E(long frag_off_e, long mask) {
            return add(Criteria.selectFrag_Off_E(frag_off_e, mask));
        }

        @Override
        public Builder selectTtl_E(long ttl_e) {
            return add(Criteria.selectTtl_E(ttl_e));
        }
  
        @Override
        public Builder selectTtl_E(long ttl_e, long mask) {
            return add(Criteria.selectTtl_E(ttl_e, mask));
        }

        @Override
        public Builder selectIpv4_E_Type(long ipv4_e_type) {
            return add(Criteria.selectIpv4_E_Type(ipv4_e_type));
        }
  
        @Override
        public Builder selectIpv4_E_Type(long ipv4_e_type, long mask) {
            return add(Criteria.selectIpv4_E_Type(ipv4_e_type, mask));
        }

        @Override
        public Builder selectIp_Check_E(long ip_check_e) {
            return add(Criteria.selectIp_Check_E(ip_check_e));
        }
  
        @Override
        public Builder selectIp_Check_E(long ip_check_e, long mask) {
            return add(Criteria.selectIp_Check_E(ip_check_e, mask));
        }

        @Override
        public Builder selectIp_Saddr_E(long ip_saddr_e) {
            return add(Criteria.selectIp_Saddr_E(ip_saddr_e));
        }
  
        @Override
        public Builder selectIp_Saddr_E(long ip_saddr_e, long mask) {
            return add(Criteria.selectIp_Saddr_E(ip_saddr_e, mask));
        }

        @Override
        public Builder selectIp_Daddr_E(long ip_daddr_e) {
            return add(Criteria.selectIp_Daddr_E(ip_daddr_e));
        }
  
        @Override
        public Builder selectIp_Daddr_E(long ip_daddr_e, long mask) {
            return add(Criteria.selectIp_Daddr_E(ip_daddr_e, mask));
        }

        @Override
        public Builder selectIpv6_Ver_Tp_Flb_E(long ipv6_ver_tp_flb_e) {
            return add(Criteria.selectIpv6_Ver_Tp_Flb_E(ipv6_ver_tp_flb_e));
        }
  
        @Override
        public Builder selectIpv6_Ver_Tp_Flb_E(long ipv6_ver_tp_flb_e, long mask) {
            return add(Criteria.selectIpv6_Ver_Tp_Flb_E(ipv6_ver_tp_flb_e, mask));
        }

        @Override
        public Builder selectIpv6_Plen_E(long ipv6_plen_e) {
            return add(Criteria.selectIpv6_Plen_E(ipv6_plen_e));
        }
  
        @Override
        public Builder selectIpv6_Plen_E(long ipv6_plen_e, long mask) {
            return add(Criteria.selectIpv6_Plen_E(ipv6_plen_e, mask));
        }

        @Override
        public Builder selectIpv6_E_Type(long ipv6_e_type) {
            return add(Criteria.selectIpv6_E_Type(ipv6_e_type));
        }
  
        @Override
        public Builder selectIpv6_E_Type(long ipv6_e_type, long mask) {
            return add(Criteria.selectIpv6_E_Type(ipv6_e_type, mask));
        }

        @Override
        public Builder selectIpv6_Hlmt_E(long ipv6_hlmt_e) {
            return add(Criteria.selectIpv6_Hlmt_E(ipv6_hlmt_e));
        }
  
        @Override
        public Builder selectIpv6_Hlmt_E(long ipv6_hlmt_e, long mask) {
            return add(Criteria.selectIpv6_Hlmt_E(ipv6_hlmt_e, mask));
        }

        @Override
        public Builder selectIpv6_Src_E(Ipv6_Src_E ipv6_src_e) {
            return add(Criteria.selectIpv6_Src_E(ipv6_src_e));
        }
  
        @Override
        public Builder selectIpv6_Src_E(Ipv6_Src_E ipv6_src_e, Ipv6_Src_E mask) {
            return add(Criteria.selectIpv6_Src_E(ipv6_src_e, mask));
        }

        @Override
        public Builder selectIpv6_Dst_E(Ipv6_Dst_E ipv6_dst_e) {
            return add(Criteria.selectIpv6_Dst_E(ipv6_dst_e));
        }
  
        @Override
        public Builder selectIpv6_Dst_E(Ipv6_Dst_E ipv6_dst_e, Ipv6_Dst_E mask) {
            return add(Criteria.selectIpv6_Dst_E(ipv6_dst_e, mask));
        }

        @Override
        public Builder selectTcp_Source(long tcp_source) {
            return add(Criteria.selectTcp_Source(tcp_source));
        }
  
        @Override
        public Builder selectTcp_Source(long tcp_source, long mask) {
            return add(Criteria.selectTcp_Source(tcp_source, mask));
        }

        @Override
        public Builder selectTcp_Dest(long tcp_dest) {
            return add(Criteria.selectTcp_Dest(tcp_dest));
        }
  
        @Override
        public Builder selectTcp_Dest(long tcp_dest, long mask) {
            return add(Criteria.selectTcp_Dest(tcp_dest, mask));
        }

        @Override
        public Builder selectSeq(long seq) {
            return add(Criteria.selectSeq(seq));
        }
  
        @Override
        public Builder selectSeq(long seq, long mask) {
            return add(Criteria.selectSeq(seq, mask));
        }

        @Override
        public Builder selectAck_Seq(long ack_seq) {
            return add(Criteria.selectAck_Seq(ack_seq));
        }
  
        @Override
        public Builder selectAck_Seq(long ack_seq, long mask) {
            return add(Criteria.selectAck_Seq(ack_seq, mask));
        }

        @Override
        public Builder selectOff_Bits(long off_bits) {
            return add(Criteria.selectOff_Bits(off_bits));
        }
  
        @Override
        public Builder selectOff_Bits(long off_bits, long mask) {
            return add(Criteria.selectOff_Bits(off_bits, mask));
        }

        @Override
        public Builder selectWindow(long window) {
            return add(Criteria.selectWindow(window));
        }
  
        @Override
        public Builder selectWindow(long window, long mask) {
            return add(Criteria.selectWindow(window, mask));
        }

        @Override
        public Builder selectTcp_Check(long tcp_check) {
            return add(Criteria.selectTcp_Check(tcp_check));
        }
  
        @Override
        public Builder selectTcp_Check(long tcp_check, long mask) {
            return add(Criteria.selectTcp_Check(tcp_check, mask));
        }

        @Override
        public Builder selectUrg_Ptr(long urg_ptr) {
            return add(Criteria.selectUrg_Ptr(urg_ptr));
        }
  
        @Override
        public Builder selectUrg_Ptr(long urg_ptr, long mask) {
            return add(Criteria.selectUrg_Ptr(urg_ptr, mask));
        }

        @Override
        public Builder selectUdp_Source(long udp_source) {
            return add(Criteria.selectUdp_Source(udp_source));
        }
  
        @Override
        public Builder selectUdp_Source(long udp_source, long mask) {
            return add(Criteria.selectUdp_Source(udp_source, mask));
        }

        @Override
        public Builder selectUdp_Dest(long udp_dest) {
            return add(Criteria.selectUdp_Dest(udp_dest));
        }
  
        @Override
        public Builder selectUdp_Dest(long udp_dest, long mask) {
            return add(Criteria.selectUdp_Dest(udp_dest, mask));
        }

        @Override
        public Builder selectLen(long len) {
            return add(Criteria.selectLen(len));
        }
  
        @Override
        public Builder selectLen(long len, long mask) {
            return add(Criteria.selectLen(len, mask));
        }

        @Override
        public Builder selectUdp_Check(long udp_check) {
            return add(Criteria.selectUdp_Check(udp_check));
        }
  
        @Override
        public Builder selectUdp_Check(long udp_check, long mask) {
            return add(Criteria.selectUdp_Check(udp_check, mask));
        }

        @Override
        public Builder selectSrv6_Type(long srv6_type) {
            return add(Criteria.selectSrv6_Type(srv6_type));
        }
  
        @Override
        public Builder selectSrv6_Type(long srv6_type, long mask) {
            return add(Criteria.selectSrv6_Type(srv6_type, mask));
        }

        @Override
        public Builder selectSrv6_Hdr_Ext_Len(long srv6_hdr_ext_len) {
            return add(Criteria.selectSrv6_Hdr_Ext_Len(srv6_hdr_ext_len));
        }
  
        @Override
        public Builder selectSrv6_Hdr_Ext_Len(long srv6_hdr_ext_len, long mask) {
            return add(Criteria.selectSrv6_Hdr_Ext_Len(srv6_hdr_ext_len, mask));
        }

        @Override
        public Builder selectSrv6_Routing_Type(long srv6_routing_Type) {
            return add(Criteria.selectSrv6_Routing_Type(srv6_routing_Type));
        }
  
        @Override
        public Builder selectSrv6_Routing_Type(long srv6_routing_Type, long mask) {
            return add(Criteria.selectSrv6_Routing_Type(srv6_routing_Type, mask));
        }

        @Override
        public Builder selectSrv6_Segments_Left(long srv6_segments_left) {
            return add(Criteria.selectSrv6_Segments_Left(srv6_segments_left));
        }
  
        @Override
        public Builder selectSrv6_Segments_Left(long srv6_segments_left, long mask) {
            return add(Criteria.selectSrv6_Segments_Left(srv6_segments_left, mask));
        }

        @Override
        public Builder selectSrv6_Last_Enty(long srv6_last_enty) {
            return add(Criteria.selectSrv6_Last_Enty(srv6_last_enty));
        }
  
        @Override
        public Builder selectSrv6_Last_Enty(long srv6_last_enty, long mask) {
            return add(Criteria.selectSrv6_Last_Enty(srv6_last_enty, mask));
        }

        @Override
        public Builder selectSrv6_Flags(long srv6_flags) {
            return add(Criteria.selectSrv6_Flags(srv6_flags));
        }
  
        @Override
        public Builder selectSrv6_Flags(long srv6_flags, long mask) {
            return add(Criteria.selectSrv6_Flags(srv6_flags, mask));
        }

        @Override
        public Builder selectSrv6_Tag(long srv6_tag) {
            return add(Criteria.selectSrv6_Tag(srv6_tag));
        }
  
        @Override
        public Builder selectSrv6_Tag(long srv6_tag, long mask) {
            return add(Criteria.selectSrv6_Tag(srv6_tag, mask));
        }

        @Override
        public Builder selectSrv6_Segmentlist1(Srv6_Segmentlist1 srv6_segmentlist1) {
            return add(Criteria.selectSrv6_Segmentlist1(srv6_segmentlist1));
        }
  
        @Override
        public Builder selectSrv6_Segmentlist1(Srv6_Segmentlist1 srv6_segmentlist1, Srv6_Segmentlist1 mask) {
            return add(Criteria.selectSrv6_Segmentlist1(srv6_segmentlist1, mask));
        }

        @Override
        public Builder selectSrv6_Segmentlist2(Srv6_Segmentlist2 srv6_segmentlist2) {
            return add(Criteria.selectSrv6_Segmentlist2(srv6_segmentlist2));
        }
  
        @Override
        public Builder selectSrv6_Segmentlist2(Srv6_Segmentlist2 srv6_segmentlist2, Srv6_Segmentlist2 mask) {
            return add(Criteria.selectSrv6_Segmentlist2(srv6_segmentlist2, mask));
        }

        @Override
        public Builder selectSrv6_Segmentlist3(Srv6_Segmentlist3 srv6_segmentlist3) {
            return add(Criteria.selectSrv6_Segmentlist3(srv6_segmentlist3));
        }
  
        @Override
        public Builder selectSrv6_Segmentlist3(Srv6_Segmentlist3 srv6_segmentlist3, Srv6_Segmentlist3 mask) {
            return add(Criteria.selectSrv6_Segmentlist3(srv6_segmentlist3, mask));
        }

        @Override
        public Builder selectIpv6_Ver_Tp_Flb_I(long ipv6_ver_tp_flb_i) {
            return add(Criteria.selectIpv6_Ver_Tp_Flb_I(ipv6_ver_tp_flb_i));
        }
  
        @Override
        public Builder selectIpv6_Ver_Tp_Flb_I(long ipv6_ver_tp_flb_i, long mask) {
            return add(Criteria.selectIpv6_Ver_Tp_Flb_I(ipv6_ver_tp_flb_i, mask));
        }

        @Override
        public Builder selectIpv6_Plen_I(long ipv6_plen_i) {
            return add(Criteria.selectIpv6_Plen_I(ipv6_plen_i));
        }
  
        @Override
        public Builder selectIpv6_Plen_I(long ipv6_plen_i, long mask) {
            return add(Criteria.selectIpv6_Plen_I(ipv6_plen_i, mask));
        }

        @Override
        public Builder selectIpv6_I_Type(long ipv6_i_type) {
            return add(Criteria.selectIpv6_I_Type(ipv6_i_type));
        }
  
        @Override
        public Builder selectIpv6_I_Type(long ipv6_i_type, long mask) {
            return add(Criteria.selectIpv6_I_Type(ipv6_i_type, mask));
        }

        @Override
        public Builder selectIpv6_Hlmt_I(long ipv6_hlmt_i) {
            return add(Criteria.selectIpv6_Hlmt_I(ipv6_hlmt_i));
        }
  
        @Override
        public Builder selectIpv6_Hlmt_I(long ipv6_hlmt_i, long mask) {
            return add(Criteria.selectIpv6_Hlmt_I(ipv6_hlmt_i, mask));
        }

        @Override
        public Builder selectIpv6_Src_I(Ipv6_Src_I ipv6_src_i) {
            return add(Criteria.selectIpv6_Src_I(ipv6_src_i));
        }
  
        @Override
        public Builder selectIpv6_Src_I(Ipv6_Src_I ipv6_src_i, Ipv6_Src_I mask) {
            return add(Criteria.selectIpv6_Src_I(ipv6_src_i, mask));
        }

        @Override
        public Builder selectIpv6_Dst_I(Ipv6_Dst_I ipv6_dst_i) {
            return add(Criteria.selectIpv6_Dst_I(ipv6_dst_i));
        }
  
        @Override
        public Builder selectIpv6_Dst_I(Ipv6_Dst_I ipv6_dst_i, Ipv6_Dst_I mask) {
            return add(Criteria.selectIpv6_Dst_I(ipv6_dst_i, mask));
        }

        @Override
        public Builder selectVer_Hl_I(long ver_hl_i) {
            return add(Criteria.selectVer_Hl_I(ver_hl_i));
        }
  
        @Override
        public Builder selectVer_Hl_I(long ver_hl_i, long mask) {
            return add(Criteria.selectVer_Hl_I(ver_hl_i, mask));
        }

        @Override
        public Builder selectTos_I(long tos_i) {
            return add(Criteria.selectTos_I(tos_i));
        }
  
        @Override
        public Builder selectTos_I(long tos_i, long mask) {
            return add(Criteria.selectTos_I(tos_i, mask));
        }

        @Override
        public Builder selectTot_Len_I(long tot_len_i) {
            return add(Criteria.selectTot_Len_I(tot_len_i));
        }
  
        @Override
        public Builder selectTot_Len_I(long tot_len_i, long mask) {
            return add(Criteria.selectTot_Len_I(tot_len_i, mask));
        }

        @Override
        public Builder selectIp_Id_I(long ip_id_i) {
            return add(Criteria.selectIp_Id_I(ip_id_i));
        }
  
        @Override
        public Builder selectIp_Id_I(long ip_id_i, long mask) {
            return add(Criteria.selectIp_Id_I(ip_id_i, mask));
        }

        @Override
        public Builder selectFrag_Off_I(long frag_off_i) {
            return add(Criteria.selectFrag_Off_I(frag_off_i));
        }
  
        @Override
        public Builder selectFrag_Off_I(long frag_off_i, long mask) {
            return add(Criteria.selectFrag_Off_I(frag_off_i, mask));
        }

        @Override
        public Builder selectTtl_I(long ttl_i) {
            return add(Criteria.selectTtl_I(ttl_i));
        }
  
        @Override
        public Builder selectTtl_I(long ttl_i, long mask) {
            return add(Criteria.selectTtl_I(ttl_i, mask));
        }

        @Override
        public Builder selectIpv4_I_Type(long ipv4_i_type) {
            return add(Criteria.selectIpv4_I_Type(ipv4_i_type));
        }
  
        @Override
        public Builder selectIpv4_I_Type(long ipv4_i_type, long mask) {
            return add(Criteria.selectIpv4_I_Type(ipv4_i_type, mask));
        }

        @Override
        public Builder selectIp_Check_I(long ip_check_i) {
            return add(Criteria.selectIp_Check_I(ip_check_i));
        }
  
        @Override
        public Builder selectIp_Check_I(long ip_check_i, long mask) {
            return add(Criteria.selectIp_Check_I(ip_check_i, mask));
        }

        @Override
        public Builder selectIp_Saddr_I(long ip_saddr_i) {
            return add(Criteria.selectIp_Saddr_I(ip_saddr_i));
        }
  
        @Override
        public Builder selectIp_Saddr_I(long ip_saddr_i, long mask) {
            return add(Criteria.selectIp_Saddr_I(ip_saddr_i, mask));
        }

        @Override
        public Builder selectIp_Daddr_I(long ip_daddr_i) {
            return add(Criteria.selectIp_Daddr_I(ip_daddr_i));
        }
  
        @Override
        public Builder selectIp_Daddr_I(long ip_daddr_i, long mask) {
            return add(Criteria.selectIp_Daddr_I(ip_daddr_i, mask));
        }

        @Override
        public TrafficSelector.Builder extension(ExtensionSelector extensionSelector,
                DeviceId deviceId) {
            return add(Criteria.extension(extensionSelector, deviceId));
        }

        @Override
        public DefaultTrafficSelector build() {
            return new DefaultTrafficSelector(selector.values(), extSelector.values(), match);
        }
    }

    public static DefaultTrafficSelector readFrom(ByteBuf bb){
        DefaultTrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        HashMap<Criterion.Type, Criterion.Builder> builders = new HashMap<>();

        Criterion.Builder builder = new PortCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IN_PORT, builder);
        }
        bb.skipBytes(6);  

        builder = new Mac_DstCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.MAC_DST, builder);
        }

        builder = new Mac_SrcCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.MAC_SRC, builder);
        }

        bb.skipBytes(4);

        builder = new Vlan1_TpidCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.VLAN1_TPID, builder);
        }

        builder = new Vlan1_QidCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.VLAN1_QID, builder);
        }

        builder = new Vlan2_TpidCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.VLAN2_TPID, builder);
        }

        builder = new Vlan2_QidCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.VLAN2_QID, builder);
        }

        builder = new Dl_TypeCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.DL_TYPE, builder);
        }

        bb.skipBytes(6);

        builder = new Ver_Hl_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.VER_HL_E, builder);
        }

        builder = new Tos_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.TOS_E, builder);
        }

        builder = new Tot_Len_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.TOT_LEN_E, builder);
        }

        builder = new Ip_Id_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IP_ID_E, builder);
        }

        builder = new Frag_Off_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.FRAG_OFF_E, builder);
        }

        builder = new Ttl_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.TTL_E, builder);
        }

        builder = new Ipv4_E_TypeCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV4_E_TYPE, builder);
        }

        builder = new Ip_Check_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IP_CHECK_E, builder);
        }

        builder = new Ip_Saddr_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IP_SADDR_E, builder);
        }

        builder = new Ip_Daddr_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IP_DADDR_E, builder);
        }

        bb.skipBytes(4);

        builder = new Ipv6_Ver_Tp_Flb_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_VER_TP_FLB_E, builder);
        }

        builder = new Ipv6_Plen_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_PLEN_E, builder);
        }

        builder = new Ipv6_E_TypeCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_E_TYPE, builder);
        }

        builder = new Ipv6_Hlmt_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_HLMT_E, builder);
        }

        builder = new Ipv6_Src_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_SRC_E, builder);
        }

        builder = new Ipv6_Dst_ECriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_DST_E, builder);
        }

        builder = new Tcp_SourceCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.TCP_SOURCE, builder);
        }

        builder = new Tcp_DestCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.TCP_DEST, builder);
        }

        builder = new SeqCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SEQ, builder);
        }

        builder = new Ack_SeqCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.ACK_SEQ, builder);
        }

        builder = new Off_BitsCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.OFF_BITS, builder);
        }

        builder = new WindowCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.WINDOW, builder);
        }

        builder = new Tcp_CheckCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.TCP_CHECK, builder);
        }

        builder = new Urg_PtrCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.URG_PTR, builder);
        }

        bb.skipBytes(4);

        builder = new Udp_SourceCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.UDP_SOURCE, builder);
        }

        builder = new Udp_DestCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.UDP_DEST, builder);
        }

        builder = new LenCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.LEN, builder);
        }

        builder = new Udp_CheckCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.UDP_CHECK, builder);
        }

        builder = new Srv6_TypeCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_TYPE, builder);
        }

        builder = new Srv6_Hdr_Ext_LenCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_HDR_EXT_LEN, builder);
        }

        builder = new Srv6_Routing_TypeCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_ROUTING_TYPE, builder);
        }

        builder = new Srv6_Segments_LeftCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_SEGMENTS_LEFT, builder);
        }

        builder = new Srv6_Last_EntyCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_LAST_ENTY, builder);
        }

        builder = new Srv6_FlagsCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_FLAGS, builder);
        }

        builder = new Srv6_TagCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_TAG, builder);
        }

        builder = new Srv6_Segmentlist1Criterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_SEGMENTLIST1, builder);
        }

        builder = new Srv6_Segmentlist2Criterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_SEGMENTLIST2, builder);
        }

        builder = new Srv6_Segmentlist3Criterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.SRV6_SEGMENTLIST3, builder);
        }

        builder = new Ipv6_Ver_Tp_Flb_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_VER_TP_FLB_I, builder);
        }

        builder = new Ipv6_Plen_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_PLEN_I, builder);
        }

        builder = new Ipv6_I_TypeCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_I_TYPE, builder);
        }

        builder = new Ipv6_Hlmt_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_HLMT_I, builder);
        }

        builder = new Ipv6_Src_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_SRC_I, builder);
        }

        builder = new Ipv6_Dst_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV6_DST_I, builder);
        }

        builder = new Ver_Hl_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.VER_HL_I, builder);
        }

        builder = new Tos_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.TOS_I, builder);
        }

        builder = new Tot_Len_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.TOT_LEN_I, builder);
        }

        builder = new Ip_Id_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IP_ID_I, builder);
        }

        builder = new Frag_Off_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.FRAG_OFF_I, builder);
        }

        builder = new Ttl_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.TTL_I, builder);
        }

        builder = new Ipv4_I_TypeCriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IPV4_I_TYPE, builder);
        }

        builder = new Ip_Check_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IP_CHECK_I, builder);
        }

        builder = new Ip_Saddr_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IP_SADDR_I, builder);
        }

        builder = new Ip_Daddr_ICriterion.Builder();
        if(builder.readMask(bb)){
            builders.put(Criterion.Type.IP_DADDR_I, builder);
        }

        bb.skipBytes(4);

        if(builders.containsKey(Criterion.Type.IN_PORT)){
            trafficSelector.add(builders.get(Criterion.Type.IN_PORT)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(PortCriterion.LEN);
        }
        bb.skipBytes(6);

        if(builders.containsKey(Criterion.Type.MAC_DST)){
            trafficSelector.add(builders.get(Criterion.Type.MAC_DST)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Mac_DstCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.MAC_SRC)){
            trafficSelector.add(builders.get(Criterion.Type.MAC_SRC)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Mac_SrcCriterion.LEN);
        }

        bb.skipBytes(4);

        if(builders.containsKey(Criterion.Type.VLAN1_TPID)){
            trafficSelector.add(builders.get(Criterion.Type.VLAN1_TPID)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Vlan1_TpidCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.VLAN1_QID)){
            trafficSelector.add(builders.get(Criterion.Type.VLAN1_QID)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Vlan1_QidCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.VLAN2_TPID)){
            trafficSelector.add(builders.get(Criterion.Type.VLAN2_TPID)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Vlan2_TpidCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.VLAN2_QID)){
            trafficSelector.add(builders.get(Criterion.Type.VLAN2_QID)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Vlan2_QidCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.DL_TYPE)){
            trafficSelector.add(builders.get(Criterion.Type.DL_TYPE)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Dl_TypeCriterion.LEN);
        }

        bb.skipBytes(6);

        if(builders.containsKey(Criterion.Type.VER_HL_E)){
            trafficSelector.add(builders.get(Criterion.Type.VER_HL_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ver_Hl_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.TOS_E)){
            trafficSelector.add(builders.get(Criterion.Type.TOS_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Tos_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.TOT_LEN_E)){
            trafficSelector.add(builders.get(Criterion.Type.TOT_LEN_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Tot_Len_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IP_ID_E)){
            trafficSelector.add(builders.get(Criterion.Type.IP_ID_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ip_Id_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.FRAG_OFF_E)){
            trafficSelector.add(builders.get(Criterion.Type.FRAG_OFF_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Frag_Off_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.TTL_E)){
            trafficSelector.add(builders.get(Criterion.Type.TTL_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ttl_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV4_E_TYPE)){
            trafficSelector.add(builders.get(Criterion.Type.IPV4_E_TYPE)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv4_E_TypeCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IP_CHECK_E)){
            trafficSelector.add(builders.get(Criterion.Type.IP_CHECK_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ip_Check_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IP_SADDR_E)){
            trafficSelector.add(builders.get(Criterion.Type.IP_SADDR_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ip_Saddr_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IP_DADDR_E)){
            trafficSelector.add(builders.get(Criterion.Type.IP_DADDR_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ip_Daddr_ECriterion.LEN);
        }

        bb.skipBytes(4);

        if(builders.containsKey(Criterion.Type.IPV6_VER_TP_FLB_E)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_VER_TP_FLB_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Ver_Tp_Flb_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_PLEN_E)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_PLEN_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Plen_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_E_TYPE)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_E_TYPE)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_E_TypeCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_HLMT_E)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_HLMT_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Hlmt_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_SRC_E)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_SRC_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Src_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_DST_E)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_DST_E)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Dst_ECriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.TCP_SOURCE)){
            trafficSelector.add(builders.get(Criterion.Type.TCP_SOURCE)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Tcp_SourceCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.TCP_DEST)){
            trafficSelector.add(builders.get(Criterion.Type.TCP_DEST)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Tcp_DestCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SEQ)){
            trafficSelector.add(builders.get(Criterion.Type.SEQ)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(SeqCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.ACK_SEQ)){
            trafficSelector.add(builders.get(Criterion.Type.ACK_SEQ)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ack_SeqCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.OFF_BITS)){
            trafficSelector.add(builders.get(Criterion.Type.OFF_BITS)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Off_BitsCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.WINDOW)){
            trafficSelector.add(builders.get(Criterion.Type.WINDOW)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(WindowCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.TCP_CHECK)){
            trafficSelector.add(builders.get(Criterion.Type.TCP_CHECK)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Tcp_CheckCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.URG_PTR)){
            trafficSelector.add(builders.get(Criterion.Type.URG_PTR)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Urg_PtrCriterion.LEN);
        }

        bb.skipBytes(4);

        if(builders.containsKey(Criterion.Type.UDP_SOURCE)){
            trafficSelector.add(builders.get(Criterion.Type.UDP_SOURCE)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Udp_SourceCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.UDP_DEST)){
            trafficSelector.add(builders.get(Criterion.Type.UDP_DEST)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Udp_DestCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.LEN)){
            trafficSelector.add(builders.get(Criterion.Type.LEN)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(LenCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.UDP_CHECK)){
            trafficSelector.add(builders.get(Criterion.Type.UDP_CHECK)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Udp_CheckCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_TYPE)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_TYPE)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_TypeCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_HDR_EXT_LEN)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_HDR_EXT_LEN)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_Hdr_Ext_LenCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_ROUTING_TYPE)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_ROUTING_TYPE)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_Routing_TypeCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_SEGMENTS_LEFT)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_SEGMENTS_LEFT)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_Segments_LeftCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_LAST_ENTY)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_LAST_ENTY)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_Last_EntyCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_FLAGS)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_FLAGS)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_FlagsCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_TAG)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_TAG)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_TagCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_SEGMENTLIST1)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_SEGMENTLIST1)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_Segmentlist1Criterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_SEGMENTLIST2)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_SEGMENTLIST2)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_Segmentlist2Criterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.SRV6_SEGMENTLIST3)){
            trafficSelector.add(builders.get(Criterion.Type.SRV6_SEGMENTLIST3)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Srv6_Segmentlist3Criterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_VER_TP_FLB_I)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_VER_TP_FLB_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Ver_Tp_Flb_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_PLEN_I)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_PLEN_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Plen_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_I_TYPE)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_I_TYPE)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_I_TypeCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_HLMT_I)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_HLMT_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Hlmt_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_SRC_I)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_SRC_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Src_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV6_DST_I)){
            trafficSelector.add(builders.get(Criterion.Type.IPV6_DST_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv6_Dst_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.VER_HL_I)){
            trafficSelector.add(builders.get(Criterion.Type.VER_HL_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ver_Hl_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.TOS_I)){
            trafficSelector.add(builders.get(Criterion.Type.TOS_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Tos_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.TOT_LEN_I)){
            trafficSelector.add(builders.get(Criterion.Type.TOT_LEN_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Tot_Len_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IP_ID_I)){
            trafficSelector.add(builders.get(Criterion.Type.IP_ID_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ip_Id_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.FRAG_OFF_I)){
            trafficSelector.add(builders.get(Criterion.Type.FRAG_OFF_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Frag_Off_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.TTL_I)){
            trafficSelector.add(builders.get(Criterion.Type.TTL_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ttl_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IPV4_I_TYPE)){
            trafficSelector.add(builders.get(Criterion.Type.IPV4_I_TYPE)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ipv4_I_TypeCriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IP_CHECK_I)){
            trafficSelector.add(builders.get(Criterion.Type.IP_CHECK_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ip_Check_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IP_SADDR_I)){
            trafficSelector.add(builders.get(Criterion.Type.IP_SADDR_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ip_Saddr_ICriterion.LEN);
        }

        if(builders.containsKey(Criterion.Type.IP_DADDR_I)){
            trafficSelector.add(builders.get(Criterion.Type.IP_DADDR_I)
                                        .readData(bb)
                                        .build());
        }else{
            bb.skipBytes(Ip_Daddr_ICriterion.LEN);
        }

        bb.skipBytes(4);

        return trafficSelector.build();
    }

    public static void writeStatsFlowRequestAllMatch(ByteBuf bb){

        bb.writeZero(8);
        bb.writeZero(248);
    
        bb.writeZero(8);
        bb.writeZero(248);

    }
    @Override
    public void writeTo(ByteBuf bb) {
        log.info("DefaultTrafficSelector ready to write!!!");
        //mof
        // flow flow_mask pad

        // flow
        //before ETH_DST
        bb.writeZero(472);  

        if(match.containsKey(Criterion.Type.MAC_DST)){
            match.get(Criterion.Type.MAC_DST).write(bb);
        }else{
            Mac_DstCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.MAC_SRC)){
            match.get(Criterion.Type.MAC_SRC).write(bb);
        }else{
            Mac_SrcCriterion.writeZero(bb);
        }

        bb.writeZero(4);

        if(match.containsKey(Criterion.Type.VLAN1_TPID)){
            match.get(Criterion.Type.VLAN1_TPID).write(bb);
        }else{
            Vlan1_TpidCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.VLAN1_QID)){
            match.get(Criterion.Type.VLAN1_QID).write(bb);
        }else{
            Vlan1_QidCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.VLAN2_TPID)){
            match.get(Criterion.Type.VLAN2_TPID).write(bb);
        }else{
            Vlan2_TpidCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.VLAN2_QID)){
            match.get(Criterion.Type.VLAN2_QID).write(bb);
        }else{
            Vlan2_QidCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.DL_TYPE)){
            match.get(Criterion.Type.DL_TYPE).write(bb);
        }else{
            Dl_TypeCriterion.writeZero(bb);
        }

        bb.writeZero(6);

        if(match.containsKey(Criterion.Type.VER_HL_E)){
            match.get(Criterion.Type.VER_HL_E).write(bb);
        }else{
            Ver_Hl_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TOS_E)){
            match.get(Criterion.Type.TOS_E).write(bb);
        }else{
            Tos_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TOT_LEN_E)){
            match.get(Criterion.Type.TOT_LEN_E).write(bb);
        }else{
            Tot_Len_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_ID_E)){
            match.get(Criterion.Type.IP_ID_E).write(bb);
        }else{
            Ip_Id_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.FRAG_OFF_E)){
            match.get(Criterion.Type.FRAG_OFF_E).write(bb);
        }else{
            Frag_Off_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TTL_E)){
            match.get(Criterion.Type.TTL_E).write(bb);
        }else{
            Ttl_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV4_E_TYPE)){
            match.get(Criterion.Type.IPV4_E_TYPE).write(bb);
        }else{
            Ipv4_E_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_CHECK_E)){
            match.get(Criterion.Type.IP_CHECK_E).write(bb);
        }else{
            Ip_Check_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_SADDR_E)){
            match.get(Criterion.Type.IP_SADDR_E).write(bb);
        }else{
            Ip_Saddr_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_DADDR_E)){
            match.get(Criterion.Type.IP_DADDR_E).write(bb);
        }else{
            Ip_Daddr_ECriterion.writeZero(bb);
        }

        bb.writeZero(4);

        if(match.containsKey(Criterion.Type.IPV6_VER_TP_FLB_E)){
            match.get(Criterion.Type.IPV6_VER_TP_FLB_E).write(bb);
        }else{
            Ipv6_Ver_Tp_Flb_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_PLEN_E)){
            match.get(Criterion.Type.IPV6_PLEN_E).write(bb);
        }else{
            Ipv6_Plen_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_E_TYPE)){
            match.get(Criterion.Type.IPV6_E_TYPE).write(bb);
        }else{
            Ipv6_E_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_HLMT_E)){
            match.get(Criterion.Type.IPV6_HLMT_E).write(bb);
        }else{
            Ipv6_Hlmt_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_SRC_E)){
            match.get(Criterion.Type.IPV6_SRC_E).write(bb);
        }else{
            Ipv6_Src_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_DST_E)){
            match.get(Criterion.Type.IPV6_DST_E).write(bb);
        }else{
            Ipv6_Dst_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TCP_SOURCE)){
            match.get(Criterion.Type.TCP_SOURCE).write(bb);
        }else{
            Tcp_SourceCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TCP_DEST)){
            match.get(Criterion.Type.TCP_DEST).write(bb);
        }else{
            Tcp_DestCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SEQ)){
            match.get(Criterion.Type.SEQ).write(bb);
        }else{
            SeqCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.ACK_SEQ)){
            match.get(Criterion.Type.ACK_SEQ).write(bb);
        }else{
            Ack_SeqCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.OFF_BITS)){
            match.get(Criterion.Type.OFF_BITS).write(bb);
        }else{
            Off_BitsCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.WINDOW)){
            match.get(Criterion.Type.WINDOW).write(bb);
        }else{
            WindowCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TCP_CHECK)){
            match.get(Criterion.Type.TCP_CHECK).write(bb);
        }else{
            Tcp_CheckCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.URG_PTR)){
            match.get(Criterion.Type.URG_PTR).write(bb);
        }else{
            Urg_PtrCriterion.writeZero(bb);
        }

        bb.writeZero(4);

        if(match.containsKey(Criterion.Type.UDP_SOURCE)){
            match.get(Criterion.Type.UDP_SOURCE).write(bb);
        }else{
            Udp_SourceCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.UDP_DEST)){
            match.get(Criterion.Type.UDP_DEST).write(bb);
        }else{
            Udp_DestCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.LEN)){
            match.get(Criterion.Type.LEN).write(bb);
        }else{
            LenCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.UDP_CHECK)){
            match.get(Criterion.Type.UDP_CHECK).write(bb);
        }else{
            Udp_CheckCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_TYPE)){
            match.get(Criterion.Type.SRV6_TYPE).write(bb);
        }else{
            Srv6_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_HDR_EXT_LEN)){
            match.get(Criterion.Type.SRV6_HDR_EXT_LEN).write(bb);
        }else{
            Srv6_Hdr_Ext_LenCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_ROUTING_TYPE)){
            match.get(Criterion.Type.SRV6_ROUTING_TYPE).write(bb);
        }else{
            Srv6_Routing_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_SEGMENTS_LEFT)){
            match.get(Criterion.Type.SRV6_SEGMENTS_LEFT).write(bb);
        }else{
            Srv6_Segments_LeftCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_LAST_ENTY)){
            match.get(Criterion.Type.SRV6_LAST_ENTY).write(bb);
        }else{
            Srv6_Last_EntyCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_FLAGS)){
            match.get(Criterion.Type.SRV6_FLAGS).write(bb);
        }else{
            Srv6_FlagsCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_TAG)){
            match.get(Criterion.Type.SRV6_TAG).write(bb);
        }else{
            Srv6_TagCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_SEGMENTLIST1)){
            match.get(Criterion.Type.SRV6_SEGMENTLIST1).write(bb);
        }else{
            Srv6_Segmentlist1Criterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_SEGMENTLIST2)){
            match.get(Criterion.Type.SRV6_SEGMENTLIST2).write(bb);
        }else{
            Srv6_Segmentlist2Criterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_SEGMENTLIST3)){
            match.get(Criterion.Type.SRV6_SEGMENTLIST3).write(bb);
        }else{
            Srv6_Segmentlist3Criterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_VER_TP_FLB_I)){
            match.get(Criterion.Type.IPV6_VER_TP_FLB_I).write(bb);
        }else{
            Ipv6_Ver_Tp_Flb_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_PLEN_I)){
            match.get(Criterion.Type.IPV6_PLEN_I).write(bb);
        }else{
            Ipv6_Plen_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_I_TYPE)){
            match.get(Criterion.Type.IPV6_I_TYPE).write(bb);
        }else{
            Ipv6_I_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_HLMT_I)){
            match.get(Criterion.Type.IPV6_HLMT_I).write(bb);
        }else{
            Ipv6_Hlmt_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_SRC_I)){
            match.get(Criterion.Type.IPV6_SRC_I).write(bb);
        }else{
            Ipv6_Src_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_DST_I)){
            match.get(Criterion.Type.IPV6_DST_I).write(bb);
        }else{
            Ipv6_Dst_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.VER_HL_I)){
            match.get(Criterion.Type.VER_HL_I).write(bb);
        }else{
            Ver_Hl_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TOS_I)){
            match.get(Criterion.Type.TOS_I).write(bb);
        }else{
            Tos_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TOT_LEN_I)){
            match.get(Criterion.Type.TOT_LEN_I).write(bb);
        }else{
            Tot_Len_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_ID_I)){
            match.get(Criterion.Type.IP_ID_I).write(bb);
        }else{
            Ip_Id_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.FRAG_OFF_I)){
            match.get(Criterion.Type.FRAG_OFF_I).write(bb);
        }else{
            Frag_Off_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TTL_I)){
            match.get(Criterion.Type.TTL_I).write(bb);
        }else{
            Ttl_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV4_I_TYPE)){
            match.get(Criterion.Type.IPV4_I_TYPE).write(bb);
        }else{
            Ipv4_I_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_CHECK_I)){
            match.get(Criterion.Type.IP_CHECK_I).write(bb);
        }else{
            Ip_Check_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_SADDR_I)){
            match.get(Criterion.Type.IP_SADDR_I).write(bb);
        }else{
            Ip_Saddr_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_DADDR_I)){
            match.get(Criterion.Type.IP_DADDR_I).write(bb);
        }else{
            Ip_Daddr_ICriterion.writeZero(bb);
        }

        bb.writeZero(4);

        // flow_mask
        // pad_before inport
        bb.writeZero(472);

        if(match.containsKey(Criterion.Type.MAC_DST)){
            match.get(Criterion.Type.MAC_DST).writeMask(bb);
        }else{
            Mac_DstCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.MAC_SRC)){
            match.get(Criterion.Type.MAC_SRC).writeMask(bb);
        }else{
            Mac_SrcCriterion.writeZero(bb);
        }

        bb.writeZero(4);

        if(match.containsKey(Criterion.Type.VLAN1_TPID)){
            match.get(Criterion.Type.VLAN1_TPID).writeMask(bb);
        }else{
            Vlan1_TpidCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.VLAN1_QID)){
            match.get(Criterion.Type.VLAN1_QID).writeMask(bb);
        }else{
            Vlan1_QidCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.VLAN2_TPID)){
            match.get(Criterion.Type.VLAN2_TPID).writeMask(bb);
        }else{
            Vlan2_TpidCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.VLAN2_QID)){
            match.get(Criterion.Type.VLAN2_QID).writeMask(bb);
        }else{
            Vlan2_QidCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.DL_TYPE)){
            match.get(Criterion.Type.DL_TYPE).writeMask(bb);
        }else{
            Dl_TypeCriterion.writeZero(bb);
        }

        bb.writeZero(6);

        if(match.containsKey(Criterion.Type.VER_HL_E)){
            match.get(Criterion.Type.VER_HL_E).writeMask(bb);
        }else{
            Ver_Hl_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TOS_E)){
            match.get(Criterion.Type.TOS_E).writeMask(bb);
        }else{
            Tos_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TOT_LEN_E)){
            match.get(Criterion.Type.TOT_LEN_E).writeMask(bb);
        }else{
            Tot_Len_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_ID_E)){
            match.get(Criterion.Type.IP_ID_E).writeMask(bb);
        }else{
            Ip_Id_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.FRAG_OFF_E)){
            match.get(Criterion.Type.FRAG_OFF_E).writeMask(bb);
        }else{
            Frag_Off_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TTL_E)){
            match.get(Criterion.Type.TTL_E).writeMask(bb);
        }else{
            Ttl_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV4_E_TYPE)){
            match.get(Criterion.Type.IPV4_E_TYPE).writeMask(bb);
        }else{
            Ipv4_E_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_CHECK_E)){
            match.get(Criterion.Type.IP_CHECK_E).writeMask(bb);
        }else{
            Ip_Check_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_SADDR_E)){
            match.get(Criterion.Type.IP_SADDR_E).writeMask(bb);
        }else{
            Ip_Saddr_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_DADDR_E)){
            match.get(Criterion.Type.IP_DADDR_E).writeMask(bb);
        }else{
            Ip_Daddr_ECriterion.writeZero(bb);
        }

        bb.writeZero(4);

        if(match.containsKey(Criterion.Type.IPV6_VER_TP_FLB_E)){
            match.get(Criterion.Type.IPV6_VER_TP_FLB_E).writeMask(bb);
        }else{
            Ipv6_Ver_Tp_Flb_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_PLEN_E)){
            match.get(Criterion.Type.IPV6_PLEN_E).writeMask(bb);
        }else{
            Ipv6_Plen_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_E_TYPE)){
            match.get(Criterion.Type.IPV6_E_TYPE).writeMask(bb);
        }else{
            Ipv6_E_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_HLMT_E)){
            match.get(Criterion.Type.IPV6_HLMT_E).writeMask(bb);
        }else{
            Ipv6_Hlmt_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_SRC_E)){
            match.get(Criterion.Type.IPV6_SRC_E).writeMask(bb);
        }else{
            Ipv6_Src_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_DST_E)){
            match.get(Criterion.Type.IPV6_DST_E).writeMask(bb);
        }else{
            Ipv6_Dst_ECriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TCP_SOURCE)){
            match.get(Criterion.Type.TCP_SOURCE).writeMask(bb);
        }else{
            Tcp_SourceCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TCP_DEST)){
            match.get(Criterion.Type.TCP_DEST).writeMask(bb);
        }else{
            Tcp_DestCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SEQ)){
            match.get(Criterion.Type.SEQ).writeMask(bb);
        }else{
            SeqCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.ACK_SEQ)){
            match.get(Criterion.Type.ACK_SEQ).writeMask(bb);
        }else{
            Ack_SeqCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.OFF_BITS)){
            match.get(Criterion.Type.OFF_BITS).writeMask(bb);
        }else{
            Off_BitsCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.WINDOW)){
            match.get(Criterion.Type.WINDOW).writeMask(bb);
        }else{
            WindowCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TCP_CHECK)){
            match.get(Criterion.Type.TCP_CHECK).writeMask(bb);
        }else{
            Tcp_CheckCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.URG_PTR)){
            match.get(Criterion.Type.URG_PTR).writeMask(bb);
        }else{
            Urg_PtrCriterion.writeZero(bb);
        }

        bb.writeZero(4);

        if(match.containsKey(Criterion.Type.UDP_SOURCE)){
            match.get(Criterion.Type.UDP_SOURCE).writeMask(bb);
        }else{
            Udp_SourceCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.UDP_DEST)){
            match.get(Criterion.Type.UDP_DEST).writeMask(bb);
        }else{
            Udp_DestCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.LEN)){
            match.get(Criterion.Type.LEN).writeMask(bb);
        }else{
            LenCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.UDP_CHECK)){
            match.get(Criterion.Type.UDP_CHECK).writeMask(bb);
        }else{
            Udp_CheckCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_TYPE)){
            match.get(Criterion.Type.SRV6_TYPE).writeMask(bb);
        }else{
            Srv6_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_HDR_EXT_LEN)){
            match.get(Criterion.Type.SRV6_HDR_EXT_LEN).writeMask(bb);
        }else{
            Srv6_Hdr_Ext_LenCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_ROUTING_TYPE)){
            match.get(Criterion.Type.SRV6_ROUTING_TYPE).writeMask(bb);
        }else{
            Srv6_Routing_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_SEGMENTS_LEFT)){
            match.get(Criterion.Type.SRV6_SEGMENTS_LEFT).writeMask(bb);
        }else{
            Srv6_Segments_LeftCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_LAST_ENTY)){
            match.get(Criterion.Type.SRV6_LAST_ENTY).writeMask(bb);
        }else{
            Srv6_Last_EntyCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_FLAGS)){
            match.get(Criterion.Type.SRV6_FLAGS).writeMask(bb);
        }else{
            Srv6_FlagsCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_TAG)){
            match.get(Criterion.Type.SRV6_TAG).writeMask(bb);
        }else{
            Srv6_TagCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_SEGMENTLIST1)){
            match.get(Criterion.Type.SRV6_SEGMENTLIST1).writeMask(bb);
        }else{
            Srv6_Segmentlist1Criterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_SEGMENTLIST2)){
            match.get(Criterion.Type.SRV6_SEGMENTLIST2).writeMask(bb);
        }else{
            Srv6_Segmentlist2Criterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.SRV6_SEGMENTLIST3)){
            match.get(Criterion.Type.SRV6_SEGMENTLIST3).writeMask(bb);
        }else{
            Srv6_Segmentlist3Criterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_VER_TP_FLB_I)){
            match.get(Criterion.Type.IPV6_VER_TP_FLB_I).writeMask(bb);
        }else{
            Ipv6_Ver_Tp_Flb_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_PLEN_I)){
            match.get(Criterion.Type.IPV6_PLEN_I).writeMask(bb);
        }else{
            Ipv6_Plen_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_I_TYPE)){
            match.get(Criterion.Type.IPV6_I_TYPE).writeMask(bb);
        }else{
            Ipv6_I_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_HLMT_I)){
            match.get(Criterion.Type.IPV6_HLMT_I).writeMask(bb);
        }else{
            Ipv6_Hlmt_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_SRC_I)){
            match.get(Criterion.Type.IPV6_SRC_I).writeMask(bb);
        }else{
            Ipv6_Src_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV6_DST_I)){
            match.get(Criterion.Type.IPV6_DST_I).writeMask(bb);
        }else{
            Ipv6_Dst_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.VER_HL_I)){
            match.get(Criterion.Type.VER_HL_I).writeMask(bb);
        }else{
            Ver_Hl_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TOS_I)){
            match.get(Criterion.Type.TOS_I).writeMask(bb);
        }else{
            Tos_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TOT_LEN_I)){
            match.get(Criterion.Type.TOT_LEN_I).writeMask(bb);
        }else{
            Tot_Len_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_ID_I)){
            match.get(Criterion.Type.IP_ID_I).writeMask(bb);
        }else{
            Ip_Id_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.FRAG_OFF_I)){
            match.get(Criterion.Type.FRAG_OFF_I).writeMask(bb);
        }else{
            Frag_Off_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.TTL_I)){
            match.get(Criterion.Type.TTL_I).writeMask(bb);
        }else{
            Ttl_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IPV4_I_TYPE)){
            match.get(Criterion.Type.IPV4_I_TYPE).writeMask(bb);
        }else{
            Ipv4_I_TypeCriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_CHECK_I)){
            match.get(Criterion.Type.IP_CHECK_I).writeMask(bb);
        }else{
            Ip_Check_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_SADDR_I)){
            match.get(Criterion.Type.IP_SADDR_I).writeMask(bb);
        }else{
            Ip_Saddr_ICriterion.writeZero(bb);
        }

        if(match.containsKey(Criterion.Type.IP_DADDR_I)){
            match.get(Criterion.Type.IP_DADDR_I).writeMask(bb);
        }else{
            Ip_Daddr_ICriterion.writeZero(bb);
        }

        bb.writeZero(4);

        // tun pad
        bb.writeZero(2056);
        // log.info("mof match = {}", bb.toString());
    }

    public static void putTo(PrimitiveSink sink){

    }
}