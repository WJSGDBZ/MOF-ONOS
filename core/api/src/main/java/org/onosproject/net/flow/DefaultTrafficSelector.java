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
        }        @Override
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
        public Builder selectVlan1_Tpid(short vlan1_tpid) {
            return add(Criteria.selectVlan1_Tpid(vlan1_tpid));
        }
  
        @Override
        public Builder selectVlan1_Tpid(short vlan1_tpid, short mask) {
            return add(Criteria.selectVlan1_Tpid(vlan1_tpid, mask));
        }

        @Override
        public Builder selectVlan1_Qid(short vlan1_qid) {
            return add(Criteria.selectVlan1_Qid(vlan1_qid));
        }
  
        @Override
        public Builder selectVlan1_Qid(short vlan1_qid, short mask) {
            return add(Criteria.selectVlan1_Qid(vlan1_qid, mask));
        }

        @Override
        public Builder selectVlan2_Tpid(short vlan2_tpid) {
            return add(Criteria.selectVlan2_Tpid(vlan2_tpid));
        }
  
        @Override
        public Builder selectVlan2_Tpid(short vlan2_tpid, short mask) {
            return add(Criteria.selectVlan2_Tpid(vlan2_tpid, mask));
        }

        @Override
        public Builder selectVlan2_Qid(short vlan2_qid) {
            return add(Criteria.selectVlan2_Qid(vlan2_qid));
        }
  
        @Override
        public Builder selectVlan2_Qid(short vlan2_qid, short mask) {
            return add(Criteria.selectVlan2_Qid(vlan2_qid, mask));
        }

        @Override
        public Builder selectDl_Type(short dl_type) {
            return add(Criteria.selectDl_Type(dl_type));
        }
  
        @Override
        public Builder selectDl_Type(short dl_type, short mask) {
            return add(Criteria.selectDl_Type(dl_type, mask));
        }

        @Override
        public Builder selectVer_Hl_E(Byte ver_hl_e) {
            return add(Criteria.selectVer_Hl_E(ver_hl_e));
        }
  
        @Override
        public Builder selectVer_Hl_E(Byte ver_hl_e, Byte mask) {
            return add(Criteria.selectVer_Hl_E(ver_hl_e, mask));
        }

        @Override
        public Builder selectTos_E(Byte tos_e) {
            return add(Criteria.selectTos_E(tos_e));
        }
  
        @Override
        public Builder selectTos_E(Byte tos_e, Byte mask) {
            return add(Criteria.selectTos_E(tos_e, mask));
        }

        @Override
        public Builder selectTot_Len_E(short tot_len_e) {
            return add(Criteria.selectTot_Len_E(tot_len_e));
        }
  
        @Override
        public Builder selectTot_Len_E(short tot_len_e, short mask) {
            return add(Criteria.selectTot_Len_E(tot_len_e, mask));
        }

        @Override
        public Builder selectIp_Id_E(short ip_id_e) {
            return add(Criteria.selectIp_Id_E(ip_id_e));
        }
  
        @Override
        public Builder selectIp_Id_E(short ip_id_e, short mask) {
            return add(Criteria.selectIp_Id_E(ip_id_e, mask));
        }

        @Override
        public Builder selectFrag_Off_E(short frag_off_e) {
            return add(Criteria.selectFrag_Off_E(frag_off_e));
        }
  
        @Override
        public Builder selectFrag_Off_E(short frag_off_e, short mask) {
            return add(Criteria.selectFrag_Off_E(frag_off_e, mask));
        }

        @Override
        public Builder selectTtl_E(Byte ttl_e) {
            return add(Criteria.selectTtl_E(ttl_e));
        }
  
        @Override
        public Builder selectTtl_E(Byte ttl_e, Byte mask) {
            return add(Criteria.selectTtl_E(ttl_e, mask));
        }

        @Override
        public Builder selectIpv4_E_Type(Byte ipv4_e_type) {
            return add(Criteria.selectIpv4_E_Type(ipv4_e_type));
        }
  
        @Override
        public Builder selectIpv4_E_Type(Byte ipv4_e_type, Byte mask) {
            return add(Criteria.selectIpv4_E_Type(ipv4_e_type, mask));
        }

        @Override
        public Builder selectIp_Check_E(short ip_check_e) {
            return add(Criteria.selectIp_Check_E(ip_check_e));
        }
  
        @Override
        public Builder selectIp_Check_E(short ip_check_e, short mask) {
            return add(Criteria.selectIp_Check_E(ip_check_e, mask));
        }

        @Override
        public Builder selectIp_Saddr_E(int ip_saddr_e) {
            return add(Criteria.selectIp_Saddr_E(ip_saddr_e));
        }
  
        @Override
        public Builder selectIp_Saddr_E(int ip_saddr_e, int mask) {
            return add(Criteria.selectIp_Saddr_E(ip_saddr_e, mask));
        }

        @Override
        public Builder selectIp_Daddr_E(int ip_daddr_e) {
            return add(Criteria.selectIp_Daddr_E(ip_daddr_e));
        }
  
        @Override
        public Builder selectIp_Daddr_E(int ip_daddr_e, int mask) {
            return add(Criteria.selectIp_Daddr_E(ip_daddr_e, mask));
        }

        @Override
        public Builder selectIpv6_Ver_Tp_Flb_E(int ipv6_ver_tp_flb_e) {
            return add(Criteria.selectIpv6_Ver_Tp_Flb_E(ipv6_ver_tp_flb_e));
        }
  
        @Override
        public Builder selectIpv6_Ver_Tp_Flb_E(int ipv6_ver_tp_flb_e, int mask) {
            return add(Criteria.selectIpv6_Ver_Tp_Flb_E(ipv6_ver_tp_flb_e, mask));
        }

        @Override
        public Builder selectIpv6_Plen_E(short ipv6_plen_e) {
            return add(Criteria.selectIpv6_Plen_E(ipv6_plen_e));
        }
  
        @Override
        public Builder selectIpv6_Plen_E(short ipv6_plen_e, short mask) {
            return add(Criteria.selectIpv6_Plen_E(ipv6_plen_e, mask));
        }

        @Override
        public Builder selectIpv6_E_Type(Byte ipv6_e_type) {
            return add(Criteria.selectIpv6_E_Type(ipv6_e_type));
        }
  
        @Override
        public Builder selectIpv6_E_Type(Byte ipv6_e_type, Byte mask) {
            return add(Criteria.selectIpv6_E_Type(ipv6_e_type, mask));
        }

        @Override
        public Builder selectIpv6_Hlmt_E(Byte ipv6_hlmt_e) {
            return add(Criteria.selectIpv6_Hlmt_E(ipv6_hlmt_e));
        }
  
        @Override
        public Builder selectIpv6_Hlmt_E(Byte ipv6_hlmt_e, Byte mask) {
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
        public Builder selectUdp_Source(short udp_source) {
            return add(Criteria.selectUdp_Source(udp_source));
        }
  
        @Override
        public Builder selectUdp_Source(short udp_source, short mask) {
            return add(Criteria.selectUdp_Source(udp_source, mask));
        }

        @Override
        public Builder selectUdp_Dest(short udp_dest) {
            return add(Criteria.selectUdp_Dest(udp_dest));
        }
  
        @Override
        public Builder selectUdp_Dest(short udp_dest, short mask) {
            return add(Criteria.selectUdp_Dest(udp_dest, mask));
        }

        @Override
        public Builder selectLen(short len) {
            return add(Criteria.selectLen(len));
        }
  
        @Override
        public Builder selectLen(short len, short mask) {
            return add(Criteria.selectLen(len, mask));
        }

        @Override
        public Builder selectUdp_Check(short udp_check) {
            return add(Criteria.selectUdp_Check(udp_check));
        }
  
        @Override
        public Builder selectUdp_Check(short udp_check, short mask) {
            return add(Criteria.selectUdp_Check(udp_check, mask));
        }

        @Override
        public Builder selectSrv6_Type(Byte srv6_type) {
            return add(Criteria.selectSrv6_Type(srv6_type));
        }
  
        @Override
        public Builder selectSrv6_Type(Byte srv6_type, Byte mask) {
            return add(Criteria.selectSrv6_Type(srv6_type, mask));
        }

        @Override
        public Builder selectSrv6_Hdr_Ext_Len(Byte srv6_hdr_ext_len) {
            return add(Criteria.selectSrv6_Hdr_Ext_Len(srv6_hdr_ext_len));
        }
  
        @Override
        public Builder selectSrv6_Hdr_Ext_Len(Byte srv6_hdr_ext_len, Byte mask) {
            return add(Criteria.selectSrv6_Hdr_Ext_Len(srv6_hdr_ext_len, mask));
        }

        @Override
        public Builder selectSrv6_Routing_Type(Byte srv6_routing_Type) {
            return add(Criteria.selectSrv6_Routing_Type(srv6_routing_Type));
        }
  
        @Override
        public Builder selectSrv6_Routing_Type(Byte srv6_routing_Type, Byte mask) {
            return add(Criteria.selectSrv6_Routing_Type(srv6_routing_Type, mask));
        }

        @Override
        public Builder selectSrv6_Segments_Left(Byte srv6_segments_left) {
            return add(Criteria.selectSrv6_Segments_Left(srv6_segments_left));
        }
  
        @Override
        public Builder selectSrv6_Segments_Left(Byte srv6_segments_left, Byte mask) {
            return add(Criteria.selectSrv6_Segments_Left(srv6_segments_left, mask));
        }

        @Override
        public Builder selectSrv6_Last_Enty(Byte srv6_last_enty) {
            return add(Criteria.selectSrv6_Last_Enty(srv6_last_enty));
        }
  
        @Override
        public Builder selectSrv6_Last_Enty(Byte srv6_last_enty, Byte mask) {
            return add(Criteria.selectSrv6_Last_Enty(srv6_last_enty, mask));
        }

        @Override
        public Builder selectSrv6_Flags(Byte srv6_flags) {
            return add(Criteria.selectSrv6_Flags(srv6_flags));
        }
  
        @Override
        public Builder selectSrv6_Flags(Byte srv6_flags, Byte mask) {
            return add(Criteria.selectSrv6_Flags(srv6_flags, mask));
        }

        @Override
        public Builder selectSrv6_Tag(short srv6_tag) {
            return add(Criteria.selectSrv6_Tag(srv6_tag));
        }
  
        @Override
        public Builder selectSrv6_Tag(short srv6_tag, short mask) {
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
        public Builder selectIpv6_Ver_Tp_Flb_I(int ipv6_ver_tp_flb_i) {
            return add(Criteria.selectIpv6_Ver_Tp_Flb_I(ipv6_ver_tp_flb_i));
        }
  
        @Override
        public Builder selectIpv6_Ver_Tp_Flb_I(int ipv6_ver_tp_flb_i, int mask) {
            return add(Criteria.selectIpv6_Ver_Tp_Flb_I(ipv6_ver_tp_flb_i, mask));
        }

        @Override
        public Builder selectIpv6_Plen_I(short ipv6_plen_i) {
            return add(Criteria.selectIpv6_Plen_I(ipv6_plen_i));
        }
  
        @Override
        public Builder selectIpv6_Plen_I(short ipv6_plen_i, short mask) {
            return add(Criteria.selectIpv6_Plen_I(ipv6_plen_i, mask));
        }

        @Override
        public Builder selectIpv6_I_Type(Byte ipv6_i_type) {
            return add(Criteria.selectIpv6_I_Type(ipv6_i_type));
        }
  
        @Override
        public Builder selectIpv6_I_Type(Byte ipv6_i_type, Byte mask) {
            return add(Criteria.selectIpv6_I_Type(ipv6_i_type, mask));
        }

        @Override
        public Builder selectIpv6_Hlmt_I(Byte ipv6_hlmt_i) {
            return add(Criteria.selectIpv6_Hlmt_I(ipv6_hlmt_i));
        }
  
        @Override
        public Builder selectIpv6_Hlmt_I(Byte ipv6_hlmt_i, Byte mask) {
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
        return null;
    }

    public static void writeStatsFlowRequestAllMatch(ByteBuf bb){

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


    // tun pad
    bb.writeZero(2056);
    // log.info("mof match = {}", bb.toString());
  }

  public static void putTo(PrimitiveSink sink){

  }
}