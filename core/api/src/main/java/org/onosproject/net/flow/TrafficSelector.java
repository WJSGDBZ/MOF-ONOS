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

import com.google.common.annotations.Beta;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.ExtensionSelector;
import org.onosproject.net.flow.criteria.PiCriterion;
import io.netty.buffer.ByteBuf;


import java.util.Set;

import org.onlab.packet.Mac_Dst;
import org.onlab.packet.Mac_Src;
import org.onlab.packet.Ipv6_Src_E;
import org.onlab.packet.Ipv6_Dst_E;
import org.onlab.packet.Srv6_Segmentlist1;
import org.onlab.packet.Srv6_Segmentlist2;
import org.onlab.packet.Srv6_Segmentlist3;
import org.onlab.packet.Ipv6_Src_I;
import org.onlab.packet.Ipv6_Dst_I;

/**
 * Abstraction of a slice of network traffic.
 */
public interface TrafficSelector {

    void writeTo(ByteBuf bb);

    /**
     * Returns selection criteria as an ordered list.
     *
     * @return list of criteria
     */
    Set<Criterion> criteria();

    /**
     * Returns the selection criterion for a particular type, if it exists in
     * this traffic selector.
     *
     * @param type criterion type to look up
     * @return the criterion of the specified type if one exists, otherwise null
     */
    Criterion getCriterion(Criterion.Type type);

    /**
     * Builder of traffic selector entities.
     */
    interface Builder {

        /**
         * Adds a traffic selection criterion. If a same type criterion has
         * already been added, it will be replaced by this one.
         *
         * @param criterion new criterion
         * @return self
         */
        Builder add(Criterion criterion);

        /**
         * Matches an inport.
         *
         * @param port the inport
         * @return a selection builder
         */
        Builder matchInPort(PortNumber port);

        /**
         * Matches a physical inport.
         *
         * @param port the physical inport
         * @return a selection builder
         */
        Builder matchInPhyPort(PortNumber port);

        /**
         * Matches a metadata.
         *
         * @param metadata the metadata
         * @return a selection builder
         */
        Builder matchMetadata(long metadata);

        /**
         * Matches a l2 dst address.
         *
         * @param addr a l2 address
         * @return a selection builder
         */
        Builder matchEthDst(MacAddress addr);

        /**
         * Matches a l2 dst address with mask.
         *
         * @param addr a l2 address
         * @param mask a mask for an l2 address
         * @return a selection builder
         */
        Builder matchEthDstMasked(MacAddress addr, MacAddress mask);

        /**
         * Matches a l2 src address.
         *
         * @param addr a l2 address
         * @return a selection builder
         */
        Builder matchEthSrc(MacAddress addr);

        /**
         * Matches a l2 src address with mask.
         *
         * @param addr a l2 address
         * @param mask a mask for an l2 address
         * @return a selection builder
         */
        Builder matchEthSrcMasked(MacAddress addr, MacAddress mask);

        /**
         * Matches the ethernet type.
         *
         * @param ethType an ethernet type
         * @return a selection builder
         */
        Builder matchEthType(short ethType);

        /**
         * Matches the vlan id.
         *
         * @param vlanId a vlan id
         * @return a selection builder
         */
        Builder matchVlanId(VlanId vlanId);

        /**
         * Matches a vlan priority.
         *
         * @param vlanPcp a vlan priority
         * @return a selection builder
         */
        Builder matchVlanPcp(byte vlanPcp);

        /**
         * Matches the inner vlan id.
         *
         * @param vlanId a vlan id
         * @return a selection builder
         */
        Builder matchInnerVlanId(VlanId vlanId);

        /**
         * Matches a vlan priority.
         *
         * @param vlanPcp a vlan priority
         * @return a selection builder
         */
        Builder matchInnerVlanPcp(byte vlanPcp);

        /**
         * Matches an IP DSCP (6 bits in ToS field).
         *
         * @param ipDscp an IP DSCP value
         * @return a selection builder
         */
        Builder matchIPDscp(byte ipDscp);

        /**
         * Matches an IP ECN (2 bits in ToS field).
         *
         * @param ipEcn an IP ECN value
         * @return a selection builder
         */
        Builder matchIPEcn(byte ipEcn);

        /**
         * Matches the l3 protocol.
         *
         * @param proto a l3 protocol
         * @return a selection builder
         */
        Builder matchIPProtocol(byte proto);

        /**
         * Matches a l3 IPv4 address.
         *
         * @param ip a l3 address
         * @return a selection builder
         */
        Builder matchIPSrc(IpPrefix ip);

        /**
         * Matches a l3 IPv4 address.
         *
         * @param ip a l3 address
         * @return a selection builder
         */
        Builder matchIPDst(IpPrefix ip);

        /**
         * Matches a TCP source port number.
         *
         * @param tcpPort a TCP source port number
         * @return a selection builder
         */
        Builder matchTcpSrc(TpPort tcpPort);

        /**
         * Matches a TCP source port number with mask.
         *
         * @param tcpPort a TCP source port number
         * @param mask a mask for a TCP source port number
         * @return a selection builder
         */
        Builder matchTcpSrcMasked(TpPort tcpPort, TpPort mask);

        /**
         * Matches a TCP destination port number.
         *
         * @param tcpPort a TCP destination port number
         * @return a selection builder
         */
        Builder matchTcpDst(TpPort tcpPort);

        /**
         * Matches a TCP destination port number with mask.
         *
         * @param tcpPort a TCP destination port number
         * @param mask a mask for a TCP destination port number
         * @return a selection builder
         */
        Builder matchTcpDstMasked(TpPort tcpPort, TpPort mask);

        /**
         * Matches an UDP source port number.
         *
         * @param udpPort an UDP source port number
         * @return a selection builder
         */
        Builder matchUdpSrc(TpPort udpPort);

        /**
         * Matches a UDP source port number with mask.
         *
         * @param udpPort a UDP source port number
         * @param mask a mask for a UDP source port number
         * @return a selection builder
         */
        Builder matchUdpSrcMasked(TpPort udpPort, TpPort mask);

        /**
         * Matches an UDP destination port number.
         *
         * @param udpPort an UDP destination port number
         * @return a selection builder
         */
        Builder matchUdpDst(TpPort udpPort);

        /**
         * Matches a UDP destination port number with mask.
         *
         * @param udpPort a UDP destination port number
         * @param mask a mask for a UDP destination port number
         * @return a selection builder
         */
        Builder matchUdpDstMasked(TpPort udpPort, TpPort mask);

        /**
         * Matches a SCTP source port number.
         *
         * @param sctpPort a SCTP source port number
         * @return a selection builder
         */
        Builder matchSctpSrc(TpPort sctpPort);

        /**
         * Matches a SCTP source port number with mask.
         *
         * @param sctpPort a SCTP source port number
         * @param mask a mask for a SCTP source port number
         * @return a selection builder
         */
        Builder matchSctpSrcMasked(TpPort sctpPort, TpPort mask);

        /**
         * Matches a SCTP destination port number.
         *
         * @param sctpPort a SCTP destination port number
         * @return a selection builder
         */
        Builder matchSctpDst(TpPort sctpPort);

        /**
         * Matches a SCTP destination port number with mask.
         *
         * @param sctpPort a SCTP destination port number
         * @param mask a mask for a SCTP destination port number
         * @return a selection builder
         */
        Builder matchSctpDstMasked(TpPort sctpPort, TpPort mask);

        /**
         * Matches an ICMP type.
         *
         * @param icmpType an ICMP type
         * @return a selection builder
         */
        Builder matchIcmpType(byte icmpType);

        /**
         * Matches an ICMP code.
         *
         * @param icmpCode an ICMP code
         * @return a selection builder
         */
        Builder matchIcmpCode(byte icmpCode);

        /**
         * Matches a l3 IPv6 address.
         *
         * @param ip a l3 IPv6 address
         * @return a selection builder
         */
        Builder matchIPv6Src(IpPrefix ip);

        /**
         * Matches a l3 IPv6 address.
         *
         * @param ip a l3 IPv6 address
         * @return a selection builder
         */
        Builder matchIPv6Dst(IpPrefix ip);

        /**
         * Matches an IPv6 flow label.
         *
         * @param flowLabel an IPv6 flow label
         * @return a selection builder
         */
        Builder matchIPv6FlowLabel(int flowLabel);

        /**
         * Matches an ICMPv6 type.
         *
         * @param icmpv6Type an ICMPv6 type
         * @return a selection builder
         */
        Builder matchIcmpv6Type(byte icmpv6Type);

        /**
         * Matches an ICMPv6 code.
         *
         * @param icmpv6Code an ICMPv6 code
         * @return a selection builder
         */
        Builder matchIcmpv6Code(byte icmpv6Code);

        /**
         * Matches an IPv6 Neighbor Discovery target address.
         *
         * @param targetAddress an IPv6 Neighbor Discovery target address
         * @return a selection builder
         */
        Builder matchIPv6NDTargetAddress(Ip6Address targetAddress);

        /**
         * Matches an IPv6 Neighbor Discovery source link-layer address.
         *
         * @param mac an IPv6 Neighbor Discovery source link-layer address
         * @return a selection builder
         */
        Builder matchIPv6NDSourceLinkLayerAddress(MacAddress mac);

        /**
         * Matches an IPv6 Neighbor Discovery target link-layer address.
         *
         * @param mac an IPv6 Neighbor Discovery target link-layer address
         * @return a selection builder
         */
        Builder matchIPv6NDTargetLinkLayerAddress(MacAddress mac);

        /**
         * Matches on a MPLS label.
         *
         * @param mplsLabel a MPLS label.
         * @return a selection builder
         */
        Builder matchMplsLabel(MplsLabel mplsLabel);

        /**
         * Matches on a MPLS Bottom-of-Stack indicator bit.
         *
         * @param mplsBos boolean value indicating BOS=1 (true) or BOS=0 (false).
         * @return a selection builder
         */
        Builder matchMplsBos(boolean mplsBos);

        /**
         * Matches a tunnel id.
         *
         * @param tunnelId a tunnel id
         * @return a selection builder
         */
        Builder matchTunnelId(long tunnelId);

        /**
         * Matches on IPv6 Extension Header pseudo-field flags.
         *
         * @param exthdrFlags the IPv6 Extension Header pseudo-field flags
         * @return a selection builder
         */
        Builder matchIPv6ExthdrFlags(short exthdrFlags);

        /**
         * Matches a arp IPv4 destination address.
         *
         * @param addr a arp IPv4 destination address
         * @return a selection builder
         */
        Builder matchArpTpa(Ip4Address addr);

        /**
         * Matches a arp IPv4 source address.
         *
         * @param addr a arp IPv4 source address
         * @return a selection builder
         */
        Builder matchArpSpa(Ip4Address addr);

        /**
         * Matches a arp_eth_dst address.
         *
         * @param addr a arp_eth_dst address
         * @return a selection builder
         */
        Builder matchArpTha(MacAddress addr);

        /**
         * Matches a arp_eth_src address.
         *
         * @param addr a arp_eth_src address
         * @return a selection builder
         */
        Builder matchArpSha(MacAddress addr);

        /**
         * Matches a arp operation type.
         *
         * @param arpOp a arp operation type
         * @return a selection builder
         */
        Builder matchArpOp(int arpOp);

        /**
         * Matches protocol independent fields.
         *
         * @param piCriterion protocol-independent criterion
         * @return a selection builder
         */
        @Beta
        Builder matchPi(PiCriterion piCriterion);

        Builder selectInport(long inport);
        Builder selectInport(long inport, long mask);

        Builder selectMac_Dst(Mac_Dst mac_dst);
        Builder selectMac_Dst(Mac_Dst mac_dst, Mac_Dst mask);

        Builder selectMac_Src(Mac_Src mac_src);
        Builder selectMac_Src(Mac_Src mac_src, Mac_Src mask);

        Builder selectVlan1_Tpid(long vlan1_tpid);
        Builder selectVlan1_Tpid(long vlan1_tpid, long mask);

        Builder selectVlan1_Qid(long vlan1_qid);
        Builder selectVlan1_Qid(long vlan1_qid, long mask);

        Builder selectVlan2_Tpid(long vlan2_tpid);
        Builder selectVlan2_Tpid(long vlan2_tpid, long mask);

        Builder selectVlan2_Qid(long vlan2_qid);
        Builder selectVlan2_Qid(long vlan2_qid, long mask);

        Builder selectDl_Type(long dl_type);
        Builder selectDl_Type(long dl_type, long mask);

        Builder selectVer_Hl_E(long ver_hl_e);
        Builder selectVer_Hl_E(long ver_hl_e, long mask);

        Builder selectTos_E(long tos_e);
        Builder selectTos_E(long tos_e, long mask);

        Builder selectTot_Len_E(long tot_len_e);
        Builder selectTot_Len_E(long tot_len_e, long mask);

        Builder selectIp_Id_E(long ip_id_e);
        Builder selectIp_Id_E(long ip_id_e, long mask);

        Builder selectFrag_Off_E(long frag_off_e);
        Builder selectFrag_Off_E(long frag_off_e, long mask);

        Builder selectTtl_E(long ttl_e);
        Builder selectTtl_E(long ttl_e, long mask);

        Builder selectIpv4_E_Type(long ipv4_e_type);
        Builder selectIpv4_E_Type(long ipv4_e_type, long mask);

        Builder selectIp_Check_E(long ip_check_e);
        Builder selectIp_Check_E(long ip_check_e, long mask);

        Builder selectIp_Saddr_E(long ip_saddr_e);
        Builder selectIp_Saddr_E(long ip_saddr_e, long mask);

        Builder selectIp_Daddr_E(long ip_daddr_e);
        Builder selectIp_Daddr_E(long ip_daddr_e, long mask);

        Builder selectIpv6_Ver_Tp_Flb_E(long ipv6_ver_tp_flb_e);
        Builder selectIpv6_Ver_Tp_Flb_E(long ipv6_ver_tp_flb_e, long mask);

        Builder selectIpv6_Plen_E(long ipv6_plen_e);
        Builder selectIpv6_Plen_E(long ipv6_plen_e, long mask);

        Builder selectIpv6_E_Type(long ipv6_e_type);
        Builder selectIpv6_E_Type(long ipv6_e_type, long mask);

        Builder selectIpv6_Hlmt_E(long ipv6_hlmt_e);
        Builder selectIpv6_Hlmt_E(long ipv6_hlmt_e, long mask);

        Builder selectIpv6_Src_E(Ipv6_Src_E ipv6_src_e);
        Builder selectIpv6_Src_E(Ipv6_Src_E ipv6_src_e, Ipv6_Src_E mask);

        Builder selectIpv6_Dst_E(Ipv6_Dst_E ipv6_dst_e);
        Builder selectIpv6_Dst_E(Ipv6_Dst_E ipv6_dst_e, Ipv6_Dst_E mask);

        Builder selectTcp_Source(long tcp_source);
        Builder selectTcp_Source(long tcp_source, long mask);

        Builder selectTcp_Dest(long tcp_dest);
        Builder selectTcp_Dest(long tcp_dest, long mask);

        Builder selectSeq(long seq);
        Builder selectSeq(long seq, long mask);

        Builder selectAck_Seq(long ack_seq);
        Builder selectAck_Seq(long ack_seq, long mask);

        Builder selectOff_Bits(long off_bits);
        Builder selectOff_Bits(long off_bits, long mask);

        Builder selectWindow(long window);
        Builder selectWindow(long window, long mask);

        Builder selectTcp_Check(long tcp_check);
        Builder selectTcp_Check(long tcp_check, long mask);

        Builder selectUrg_Ptr(long urg_ptr);
        Builder selectUrg_Ptr(long urg_ptr, long mask);

        Builder selectUdp_Source(long udp_source);
        Builder selectUdp_Source(long udp_source, long mask);

        Builder selectUdp_Dest(long udp_dest);
        Builder selectUdp_Dest(long udp_dest, long mask);

        Builder selectLen(long len);
        Builder selectLen(long len, long mask);

        Builder selectUdp_Check(long udp_check);
        Builder selectUdp_Check(long udp_check, long mask);

        Builder selectSrv6_Type(long srv6_type);
        Builder selectSrv6_Type(long srv6_type, long mask);

        Builder selectSrv6_Hdr_Ext_Len(long srv6_hdr_ext_len);
        Builder selectSrv6_Hdr_Ext_Len(long srv6_hdr_ext_len, long mask);

        Builder selectSrv6_Routing_Type(long srv6_routing_Type);
        Builder selectSrv6_Routing_Type(long srv6_routing_Type, long mask);

        Builder selectSrv6_Segments_Left(long srv6_segments_left);
        Builder selectSrv6_Segments_Left(long srv6_segments_left, long mask);

        Builder selectSrv6_Last_Enty(long srv6_last_enty);
        Builder selectSrv6_Last_Enty(long srv6_last_enty, long mask);

        Builder selectSrv6_Flags(long srv6_flags);
        Builder selectSrv6_Flags(long srv6_flags, long mask);

        Builder selectSrv6_Tag(long srv6_tag);
        Builder selectSrv6_Tag(long srv6_tag, long mask);

        Builder selectSrv6_Segmentlist1(Srv6_Segmentlist1 srv6_segmentlist1);
        Builder selectSrv6_Segmentlist1(Srv6_Segmentlist1 srv6_segmentlist1, Srv6_Segmentlist1 mask);

        Builder selectSrv6_Segmentlist2(Srv6_Segmentlist2 srv6_segmentlist2);
        Builder selectSrv6_Segmentlist2(Srv6_Segmentlist2 srv6_segmentlist2, Srv6_Segmentlist2 mask);

        Builder selectSrv6_Segmentlist3(Srv6_Segmentlist3 srv6_segmentlist3);
        Builder selectSrv6_Segmentlist3(Srv6_Segmentlist3 srv6_segmentlist3, Srv6_Segmentlist3 mask);

        Builder selectIpv6_Ver_Tp_Flb_I(long ipv6_ver_tp_flb_i);
        Builder selectIpv6_Ver_Tp_Flb_I(long ipv6_ver_tp_flb_i, long mask);

        Builder selectIpv6_Plen_I(long ipv6_plen_i);
        Builder selectIpv6_Plen_I(long ipv6_plen_i, long mask);

        Builder selectIpv6_I_Type(long ipv6_i_type);
        Builder selectIpv6_I_Type(long ipv6_i_type, long mask);

        Builder selectIpv6_Hlmt_I(long ipv6_hlmt_i);
        Builder selectIpv6_Hlmt_I(long ipv6_hlmt_i, long mask);

        Builder selectIpv6_Src_I(Ipv6_Src_I ipv6_src_i);
        Builder selectIpv6_Src_I(Ipv6_Src_I ipv6_src_i, Ipv6_Src_I mask);

        Builder selectIpv6_Dst_I(Ipv6_Dst_I ipv6_dst_i);
        Builder selectIpv6_Dst_I(Ipv6_Dst_I ipv6_dst_i, Ipv6_Dst_I mask);

        Builder selectVer_Hl_I(long ver_hl_i);
        Builder selectVer_Hl_I(long ver_hl_i, long mask);

        Builder selectTos_I(long tos_i);
        Builder selectTos_I(long tos_i, long mask);

        Builder selectTot_Len_I(long tot_len_i);
        Builder selectTot_Len_I(long tot_len_i, long mask);

        Builder selectIp_Id_I(long ip_id_i);
        Builder selectIp_Id_I(long ip_id_i, long mask);

        Builder selectFrag_Off_I(long frag_off_i);
        Builder selectFrag_Off_I(long frag_off_i, long mask);

        Builder selectTtl_I(long ttl_i);
        Builder selectTtl_I(long ttl_i, long mask);

        Builder selectIpv4_I_Type(long ipv4_i_type);
        Builder selectIpv4_I_Type(long ipv4_i_type, long mask);

        Builder selectIp_Check_I(long ip_check_i);
        Builder selectIp_Check_I(long ip_check_i, long mask);

        Builder selectIp_Saddr_I(long ip_saddr_i);
        Builder selectIp_Saddr_I(long ip_saddr_i, long mask);

        Builder selectIp_Daddr_I(long ip_daddr_i);
        Builder selectIp_Daddr_I(long ip_daddr_i, long mask);

        /**
         * Uses an extension selector.
         *
         * @param extensionSelector extension selector
         * @param deviceId device ID
         * @return a selection builder
         */
        Builder extension(ExtensionSelector extensionSelector, DeviceId deviceId);

        /**
         * Builds an immutable traffic selector.
         *
         * @return traffic selector
         */
        TrafficSelector build();
    }
}

