package org.onosproject.net.flow.criteria;

import org.onlab.packet.EthType;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Lambda;
import org.onosproject.net.OchSignal;
import org.onosproject.net.OchSignalType;
import org.onosproject.net.OduSignalId;
import org.onosproject.net.OduSignalType;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.criteria.Criterion.Type;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.TestCriterion;

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
 * Factory class to create various traffic selection criteria.
 */
public final class Criteria {

    //TODO: incomplete type implementation. Need to implement complete list from Criterion

    // Ban construction
    private Criteria() {
    }

    /**
     * Creates a match on IN_PORT field using the specified value.
     *
     * @param port inport value
     * @return match criterion
     */
    public static Criterion matchInPort(PortNumber port) {
        return new PortCriterion(port, Type.IN_PORT);
    }

    /**
     * Creates a match on IN_PHY_PORT field using the specified value.
     *
     * @param port inport value
     * @return match criterion
     */
    public static Criterion matchInPhyPort(PortNumber port) {
        return new PortCriterion(port, Type.IN_PHY_PORT);
    }

    /**
     * Creates a match on METADATA field using the specified value.
     *
     * @param metadata metadata value (64 bits data)
     * @return match criterion
     */
    public static Criterion matchMetadata(long metadata) {
        return new MetadataCriterion(metadata);
    }

    /**
     * Creates a match on ETH_DST field using the specified value. This value
     * may be a wildcard mask.
     *
     * @param mac MAC address value or wildcard mask
     * @return match criterion
     */
    public static Criterion matchEthDst(MacAddress mac) {
        return new EthCriterion(mac, Type.ETH_DST);
    }

    /**
     * Creates a masked match on ETH_DST field using the specified value and mask.
     *
     * @param mac MAC address value
     * @param mask MAC address masking
     * @return match criterion
     */
    public static Criterion matchEthDstMasked(MacAddress mac, MacAddress mask) {
        return new EthCriterion(mac, mask, Type.ETH_DST_MASKED);
    }

    /**
     * Creates a match on ETH_SRC field using the specified value. This value
     * may be a wildcard mask.
     *
     * @param mac MAC address value or wildcard mask
     * @return match criterion
     */
    public static Criterion matchEthSrc(MacAddress mac) {
        return new EthCriterion(mac, Type.ETH_SRC);
    }

    /**
     * Creates a masked match on ETH_SRC field using the specified value and mask.
     *
     * @param mac MAC address value
     * @param mask MAC address masking
     * @return match criterion
     */
    public static Criterion matchEthSrcMasked(MacAddress mac, MacAddress mask) {
        return new EthCriterion(mac, mask, Type.ETH_SRC_MASKED);
    }

    /**
     * Creates a match on ETH_TYPE field using the specified value.
     *
     * @param ethType eth type value (16 bits unsigned integer)
     * @return match criterion
     */
    public static Criterion matchEthType(int ethType) {
        return new EthTypeCriterion(ethType);
    }

    /**
     * Creates a match on ETH_TYPE field using the specified value.
     *
     * @param ethType eth type value
     * @return match criterion
     */
    public static Criterion matchEthType(EthType ethType) {
        return new EthTypeCriterion(ethType);
    }

    /**
     * Creates a match on VLAN ID field using the specified value.
     *
     * @param vlanId vlan id value
     * @return match criterion
     */
    public static Criterion matchVlanId(VlanId vlanId) {
        return new VlanIdCriterion(vlanId);
    }

    /**
     * Creates a match on the inner VLAN ID field using the specified value.
     *
     * @param vlanId vlan id value
     * @return match criterion
     */
    public static Criterion matchInnerVlanId(VlanId vlanId) {
        return new VlanIdCriterion(vlanId, Type.INNER_VLAN_VID);
    }

    /**
     * Creates a match on VLAN PCP field using the specified value.
     *
     * @param vlanPcp vlan pcp value (3 bits)
     * @return match criterion
     */
    public static Criterion matchVlanPcp(byte vlanPcp) {
        return new VlanPcpCriterion(vlanPcp);
    }

    /**
     * Creates a match on the inner VLAN PCP field using the specified value.
     *
     * @param vlanPcp vlan pcp value (3 bits)
     * @return match criterion
     */
    public static Criterion matchInnerVlanPcp(byte vlanPcp) {
        return new VlanPcpCriterion(vlanPcp, Type.INNER_VLAN_PCP);
    }

    /**
     * Creates a match on IP DSCP field using the specified value.
     *
     * @param ipDscp ip dscp value (6 bits)
     * @return match criterion
     */
    public static Criterion matchIPDscp(byte ipDscp) {
        return new IPDscpCriterion(ipDscp);
    }

    /**
     * Creates a match on IP ECN field using the specified value.
     *
     * @param ipEcn ip ecn value (2 bits)
     * @return match criterion
     */
    public static Criterion matchIPEcn(byte ipEcn) {
        return new IPEcnCriterion(ipEcn);
    }

    /**
     * Creates a match on IP proto field using the specified value.
     *
     * @param proto ip protocol value (8 bits unsigned integer)
     * @return match criterion
     */
    public static Criterion matchIPProtocol(short proto) {
        return new IPProtocolCriterion(proto);
    }

    /**
     * Creates a match on IPv4 source field using the specified value.
     *
     * @param ip ipv4 source value
     * @return match criterion
     */
    public static Criterion matchIPSrc(IpPrefix ip) {
        return new IPCriterion(ip, Type.IPV4_SRC);
    }

    /**
     * Creates a match on IPv4 destination field using the specified value.
     *
     * @param ip ipv4 source value
     * @return match criterion
     */
    public static Criterion matchIPDst(IpPrefix ip) {
        return new IPCriterion(ip, Type.IPV4_DST);
    }

    /**
     * Creates a match on TCP source port field using the specified value.
     *
     * @param tcpPort TCP source port
     * @return match criterion
     */
    public static Criterion matchTcpSrc(TpPort tcpPort) {
        return new TcpPortCriterion(tcpPort, Type.TCP_SRC);
    }

    /**
     * Creates a masked match on TCP source port field using the specified value and mask.
     *
     * @param tcpPort TCP source port
     * @param mask TCP source port masking
     * @return match criterion
     */
    public static Criterion matchTcpSrcMasked(TpPort tcpPort, TpPort mask) {
        return new TcpPortCriterion(tcpPort, mask, Type.TCP_SRC_MASKED);
    }

    /**
     * Creates a match on TCP destination port field using the specified value.
     *
     * @param tcpPort TCP destination port
     * @return match criterion
     */
    public static Criterion matchTcpDst(TpPort tcpPort) {
        return new TcpPortCriterion(tcpPort, Type.TCP_DST);
    }

    /**
     * Creates a masked match on TCP destination port field using the specified value and mask.
     *
     * @param tcpPort TCP destination port
     * @param mask TCP destination port masking
     * @return match criterion
     */
    public static Criterion matchTcpDstMasked(TpPort tcpPort, TpPort mask) {
        return new TcpPortCriterion(tcpPort, mask, Type.TCP_DST_MASKED);
    }

    /**
     * Creates a match on TCP flags using the specified value.
     *
     * @param flags TCP flags
     * @return match criterion
     */
    public static Criterion matchTcpFlags(int flags) {
        return new TcpFlagsCriterion(flags);
    }

    /**
     * Creates a match on UDP source port field using the specified value.
     *
     * @param udpPort UDP source port
     * @return match criterion
     */
    public static Criterion matchUdpSrc(TpPort udpPort) {
        return new UdpPortCriterion(udpPort, Type.UDP_SRC);
    }

    /**
     * Creates a masked match on UDP source port field using the specified value and mask.
     *
     * @param udpPort UDP source port
     * @param mask UDP source port masking
     * @return match criterion
     */
    public static Criterion matchUdpSrcMasked(TpPort udpPort, TpPort mask) {
        return new UdpPortCriterion(udpPort, mask, Type.UDP_SRC_MASKED);
    }

    /**
     * Creates a match on UDP destination port field using the specified value.
     *
     * @param udpPort UDP destination port
     * @return match criterion
     */
    public static Criterion matchUdpDst(TpPort udpPort) {
        return new UdpPortCriterion(udpPort, Type.UDP_DST);
    }

    /**
     * Creates a masked match on UDP destination port field using the specified value and mask.
     *
     * @param udpPort UDP destination port
     * @param mask UDP destination port masking
     * @return match criterion
     */
    public static Criterion matchUdpDstMasked(TpPort udpPort, TpPort mask) {
        return new UdpPortCriterion(udpPort, mask, Type.UDP_DST_MASKED);
    }

    /**
     * Creates a match on SCTP source port field using the specified value.
     *
     * @param sctpPort SCTP source port
     * @return match criterion
     */
    public static Criterion matchSctpSrc(TpPort sctpPort) {
        return new SctpPortCriterion(sctpPort, Type.SCTP_SRC);
    }

    /**
     * Creates a masked match on SCTP source port field using the specified value and mask.
     *
     * @param sctpPort SCTP source port
     * @param mask SCTP source port masking
     * @return match criterion
     */
    public static Criterion matchSctpSrcMasked(TpPort sctpPort, TpPort mask) {
        return new SctpPortCriterion(sctpPort, mask, Type.SCTP_SRC_MASKED);
    }

    /**
     * Creates a match on SCTP destination port field using the specified
     * value.
     *
     * @param sctpPort SCTP destination port
     * @return match criterion
     */
    public static Criterion matchSctpDst(TpPort sctpPort) {
        return new SctpPortCriterion(sctpPort, Type.SCTP_DST);
    }

    /**
     * Creates a masked match on SCTP destination port field using the specified value and mask.
     *
     * @param sctpPort SCTP destination port
     * @param mask SCTP destination port masking
     * @return match criterion
     */
    public static Criterion matchSctpDstMasked(TpPort sctpPort, TpPort mask) {
        return new SctpPortCriterion(sctpPort, mask, Type.SCTP_DST_MASKED);
    }

    /**
     * Creates a match on ICMP type field using the specified value.
     *
     * @param icmpType ICMP type (8 bits unsigned integer)
     * @return match criterion
     */
    public static Criterion matchIcmpType(short icmpType) {
        return new IcmpTypeCriterion(icmpType);
    }

    /**
     * Creates a match on ICMP code field using the specified value.
     *
     * @param icmpCode ICMP code (8 bits unsigned integer)
     * @return match criterion
     */
    public static Criterion matchIcmpCode(short icmpCode) {
        return new IcmpCodeCriterion(icmpCode);
    }

    /**
     * Creates a match on IPv6 source field using the specified value.
     *
     * @param ip ipv6 source value
     * @return match criterion
     */
    public static Criterion matchIPv6Src(IpPrefix ip) {
        return new IPCriterion(ip, Type.IPV6_SRC);
    }

    /**
     * Creates a match on IPv6 destination field using the specified value.
     *
     * @param ip ipv6 destination value
     * @return match criterion
     */
    public static Criterion matchIPv6Dst(IpPrefix ip) {
        return new IPCriterion(ip, Type.IPV6_DST);
    }

    /**
     * Creates a match on IPv6 flow label field using the specified value.
     *
     * @param flowLabel IPv6 flow label (20 bits)
     * @return match criterion
     */
    public static Criterion matchIPv6FlowLabel(int flowLabel) {
        return new IPv6FlowLabelCriterion(flowLabel);
    }

    /**
     * Creates a match on ICMPv6 type field using the specified value.
     *
     * @param icmpv6Type ICMPv6 type (8 bits unsigned integer)
     * @return match criterion
     */
    public static Criterion matchIcmpv6Type(short icmpv6Type) {
        return new Icmpv6TypeCriterion(icmpv6Type);
    }

    /**
     * Creates a match on ICMPv6 code field using the specified value.
     *
     * @param icmpv6Code ICMPv6 code (8 bits unsigned integer)
     * @return match criterion
     */
    public static Criterion matchIcmpv6Code(short icmpv6Code) {
        return new Icmpv6CodeCriterion(icmpv6Code);
    }

    /**
     * Creates a match on IPv6 Neighbor Discovery target address using the
     * specified value.
     *
     * @param targetAddress IPv6 Neighbor Discovery target address
     * @return match criterion
     */
    public static Criterion matchIPv6NDTargetAddress(Ip6Address targetAddress) {
        return new IPv6NDTargetAddressCriterion(targetAddress);
    }

    /**
     * Creates a match on IPv6 Neighbor Discovery source link-layer address
     * using the specified value.
     *
     * @param mac IPv6 Neighbor Discovery source link-layer address
     * @return match criterion
     */
    public static Criterion matchIPv6NDSourceLinkLayerAddress(MacAddress mac) {
        return new IPv6NDLinkLayerAddressCriterion(mac, Type.IPV6_ND_SLL);
    }

    /**
     * Creates a match on IPv6 Neighbor Discovery target link-layer address
     * using the specified value.
     *
     * @param mac IPv6 Neighbor Discovery target link-layer address
     * @return match criterion
     */
    public static Criterion matchIPv6NDTargetLinkLayerAddress(MacAddress mac) {
        return new IPv6NDLinkLayerAddressCriterion(mac, Type.IPV6_ND_TLL);
    }

    /**
     * Creates a match on MPLS label.
     *
     * @param mplsLabel MPLS label (20 bits)
     * @return match criterion
     */
    public static Criterion matchMplsLabel(MplsLabel mplsLabel) {
        return new MplsCriterion(mplsLabel);
    }

    /**
     * Creates a match on MPLS Bottom-of-Stack indicator bit.
     *
     * @param mplsBos boolean value indicating true (BOS=1) or false (BOS=0)
     * @return match criterion
     */
    public static Criterion matchMplsBos(boolean mplsBos) {
        return new MplsBosCriterion(mplsBos);
    }

    /**
     * Creates a match on MPLS TC.
     *
     * @param mplsTc MPLS TC (3 bits)
     * @return match criterion
     */
    public static Criterion matchMplsTc(byte mplsTc) {
        return new MplsTcCriterion(mplsTc);
    }

    /**
     * Creates a match on Tunnel ID.
     *
     * @param tunnelId Tunnel ID (64 bits)
     * @return match criterion
     */
    public static Criterion matchTunnelId(long tunnelId) {
        return new TunnelIdCriterion(tunnelId);
    }

    /**
     * Creates a match on IPv6 Extension Header pseudo-field fiags.
     * Those are defined in Criterion.IPv6ExthdrFlags.
     *
     * @param exthdrFlags IPv6 Extension Header pseudo-field flags (16 bits)
     * @return match criterion
     */
    public static Criterion matchIPv6ExthdrFlags(int exthdrFlags) {
        return new IPv6ExthdrFlagsCriterion(exthdrFlags);
    }

    /**
     * Creates a match on lambda using the specified value.
     *
     * @param lambda lambda
     * @return match criterion
     */
    public static Criterion matchLambda(Lambda lambda) {
        if (lambda instanceof OchSignal) {
            return new OchSignalCriterion((OchSignal) lambda);
        } else {
            throw new UnsupportedOperationException(String.format("Unsupported type of Lambda: %s", lambda));
        }
    }

    /**
     * Create a match on OCh (Optical Channel) signal type.
     *
     * @param signalType OCh signal type
     * @return match criterion
     */
    public static Criterion matchOchSignalType(OchSignalType signalType) {
        return new OchSignalTypeCriterion(signalType);
    }

    /**
     * Creates a match on ODU (Optical channel Data Unit) signal ID using the specified value.
     *
     * @param oduSignalId ODU Signal Id
     * @return match criterion
     */
    public static Criterion matchOduSignalId(OduSignalId oduSignalId) {
        return new OduSignalIdCriterion(oduSignalId);
    }

    /**
     * Creates a match on ODU (Optical channel Data Unit) signal Type using the specified value.
     *
     * @param signalType ODU Signal Type
     * @return match criterion
     */
    public static Criterion matchOduSignalType(OduSignalType signalType) {
        return new OduSignalTypeCriterion(signalType);
    }

    /**
     * Creates a match on IPv4 destination field using the specified value.
     *
     * @param ip ipv4 destination value
     * @return match criterion
     */
    public static Criterion matchArpTpa(Ip4Address ip) {
        return new ArpPaCriterion(ip, Type.ARP_TPA);
    }

    /**
     * Creates a match on IPv4 source field using the specified value.
     *
     * @param ip ipv4 source value
     * @return match criterion
     */
    public static Criterion matchArpSpa(Ip4Address ip) {
        return new ArpPaCriterion(ip, Type.ARP_SPA);
    }

    /**
     * Creates a match on MAC destination field using the specified value.
     *
     * @param mac MAC destination value
     * @return match criterion
     */
    public static Criterion matchArpTha(MacAddress mac) {
        return new ArpHaCriterion(mac, Type.ARP_THA);
    }

    /**
     * Creates a match on MAC source field using the specified value.
     *
     * @param mac MAC source value
     * @return match criterion
     */
    public static Criterion matchArpSha(MacAddress mac) {
        return new ArpHaCriterion(mac, Type.ARP_SHA);
    }

    /**
     * Creates a match on arp operation type field using the specified value.
     *
     * @param arpOp arp operation type value
     * @return match criterion
     */
    public static Criterion matchArpOp(int arpOp) {
        return new ArpOpCriterion(arpOp, Type.ARP_OP);
    }

    /**
     * Creates a match on PBB I-SID field using the specific value.
     *
     * @param pbbIsid PBB I-SID
     * @return match criterion
     */
    public static Criterion matchPbbIsid(int pbbIsid) {
        return new PbbIsidCriterion(pbbIsid);
    }

    /**
     * Creates an extension criterion for the specified extension selector.
     *
     * @param extensionSelector extension selector
     * @param deviceId device ID
     * @return match extension criterion
     */
    public static ExtensionCriterion extension(ExtensionSelector extensionSelector,
                                      DeviceId deviceId) {
        return new ExtensionCriterion(extensionSelector, deviceId);
    }

    /**
     * Creates a dummy criterion.
     *
     * @return match criterion
     */
    public static Criterion dummy() {
        return new DummyCriterion();
    }

    public static Criterion selectMac_Dst(Mac_Dst mac_dst) {
        return new Mac_DstCriterion(mac_dst);
    }
  
    public static Criterion selectMac_Dst(Mac_Dst mac_dst, Mac_Dst mask) {
        return new Mac_DstCriterion(mac_dst, mask);
    }

    public static Criterion selectMac_Src(Mac_Src mac_src) {
        return new Mac_SrcCriterion(mac_src);
    }
  
    public static Criterion selectMac_Src(Mac_Src mac_src, Mac_Src mask) {
        return new Mac_SrcCriterion(mac_src, mask);
    }

    public static Criterion selectVlan1_Tpid(long vlan1_tpid) {
        return new Vlan1_TpidCriterion(vlan1_tpid);
    }
  
    public static Criterion selectVlan1_Tpid(long vlan1_tpid, long mask) {
        return new Vlan1_TpidCriterion(vlan1_tpid, mask);
    }

    public static Criterion selectVlan1_Qid(long vlan1_qid) {
        return new Vlan1_QidCriterion(vlan1_qid);
    }
  
    public static Criterion selectVlan1_Qid(long vlan1_qid, long mask) {
        return new Vlan1_QidCriterion(vlan1_qid, mask);
    }

    public static Criterion selectVlan2_Tpid(long vlan2_tpid) {
        return new Vlan2_TpidCriterion(vlan2_tpid);
    }
  
    public static Criterion selectVlan2_Tpid(long vlan2_tpid, long mask) {
        return new Vlan2_TpidCriterion(vlan2_tpid, mask);
    }

    public static Criterion selectVlan2_Qid(long vlan2_qid) {
        return new Vlan2_QidCriterion(vlan2_qid);
    }
  
    public static Criterion selectVlan2_Qid(long vlan2_qid, long mask) {
        return new Vlan2_QidCriterion(vlan2_qid, mask);
    }

    public static Criterion selectDl_Type(long dl_type) {
        return new Dl_TypeCriterion(dl_type);
    }
  
    public static Criterion selectDl_Type(long dl_type, long mask) {
        return new Dl_TypeCriterion(dl_type, mask);
    }

    public static Criterion selectVer_Hl_E(long ver_hl_e) {
        return new Ver_Hl_ECriterion(ver_hl_e);
    }
  
    public static Criterion selectVer_Hl_E(long ver_hl_e, long mask) {
        return new Ver_Hl_ECriterion(ver_hl_e, mask);
    }

    public static Criterion selectTos_E(long tos_e) {
        return new Tos_ECriterion(tos_e);
    }
  
    public static Criterion selectTos_E(long tos_e, long mask) {
        return new Tos_ECriterion(tos_e, mask);
    }

    public static Criterion selectTot_Len_E(long tot_len_e) {
        return new Tot_Len_ECriterion(tot_len_e);
    }
  
    public static Criterion selectTot_Len_E(long tot_len_e, long mask) {
        return new Tot_Len_ECriterion(tot_len_e, mask);
    }

    public static Criterion selectIp_Id_E(long ip_id_e) {
        return new Ip_Id_ECriterion(ip_id_e);
    }
  
    public static Criterion selectIp_Id_E(long ip_id_e, long mask) {
        return new Ip_Id_ECriterion(ip_id_e, mask);
    }

    public static Criterion selectFrag_Off_E(long frag_off_e) {
        return new Frag_Off_ECriterion(frag_off_e);
    }
  
    public static Criterion selectFrag_Off_E(long frag_off_e, long mask) {
        return new Frag_Off_ECriterion(frag_off_e, mask);
    }

    public static Criterion selectTtl_E(long ttl_e) {
        return new Ttl_ECriterion(ttl_e);
    }
  
    public static Criterion selectTtl_E(long ttl_e, long mask) {
        return new Ttl_ECriterion(ttl_e, mask);
    }

    public static Criterion selectIpv4_E_Type(long ipv4_e_type) {
        return new Ipv4_E_TypeCriterion(ipv4_e_type);
    }
  
    public static Criterion selectIpv4_E_Type(long ipv4_e_type, long mask) {
        return new Ipv4_E_TypeCriterion(ipv4_e_type, mask);
    }

    public static Criterion selectIp_Check_E(long ip_check_e) {
        return new Ip_Check_ECriterion(ip_check_e);
    }
  
    public static Criterion selectIp_Check_E(long ip_check_e, long mask) {
        return new Ip_Check_ECriterion(ip_check_e, mask);
    }

    public static Criterion selectIp_Saddr_E(long ip_saIp_Saddr_Er_e) {
        return new Ip_Saddr_ECriterion(ip_saIp_Saddr_Er_e);
    }
  
    public static Criterion selectIp_Saddr_E(long ip_saIp_Saddr_Er_e, long mask) {
        return new Ip_Saddr_ECriterion(ip_saIp_Saddr_Er_e, mask);
    }

    public static Criterion selectIp_Daddr_E(long ip_daIp_Daddr_Er_e) {
        return new Ip_Daddr_ECriterion(ip_daIp_Daddr_Er_e);
    }
  
    public static Criterion selectIp_Daddr_E(long ip_daIp_Daddr_Er_e, long mask) {
        return new Ip_Daddr_ECriterion(ip_daIp_Daddr_Er_e, mask);
    }

    public static Criterion selectIpv6_Ver_Tp_Flb_E(long ipv6_ver_tp_flb_e) {
        return new Ipv6_Ver_Tp_Flb_ECriterion(ipv6_ver_tp_flb_e);
    }
  
    public static Criterion selectIpv6_Ver_Tp_Flb_E(long ipv6_ver_tp_flb_e, long mask) {
        return new Ipv6_Ver_Tp_Flb_ECriterion(ipv6_ver_tp_flb_e, mask);
    }

    public static Criterion selectIpv6_Plen_E(long ipv6_plen_e) {
        return new Ipv6_Plen_ECriterion(ipv6_plen_e);
    }
  
    public static Criterion selectIpv6_Plen_E(long ipv6_plen_e, long mask) {
        return new Ipv6_Plen_ECriterion(ipv6_plen_e, mask);
    }

    public static Criterion selectIpv6_E_Type(long ipv6_e_type) {
        return new Ipv6_E_TypeCriterion(ipv6_e_type);
    }
  
    public static Criterion selectIpv6_E_Type(long ipv6_e_type, long mask) {
        return new Ipv6_E_TypeCriterion(ipv6_e_type, mask);
    }

    public static Criterion selectIpv6_Hlmt_E(long ipv6_hlmt_e) {
        return new Ipv6_Hlmt_ECriterion(ipv6_hlmt_e);
    }
  
    public static Criterion selectIpv6_Hlmt_E(long ipv6_hlmt_e, long mask) {
        return new Ipv6_Hlmt_ECriterion(ipv6_hlmt_e, mask);
    }

    public static Criterion selectIpv6_Src_E(Ipv6_Src_E ipv6_src_e) {
        return new Ipv6_Src_ECriterion(ipv6_src_e);
    }
  
    public static Criterion selectIpv6_Src_E(Ipv6_Src_E ipv6_src_e, Ipv6_Src_E mask) {
        return new Ipv6_Src_ECriterion(ipv6_src_e, mask);
    }

    public static Criterion selectIpv6_Dst_E(Ipv6_Dst_E ipv6_dst_e) {
        return new Ipv6_Dst_ECriterion(ipv6_dst_e);
    }
  
    public static Criterion selectIpv6_Dst_E(Ipv6_Dst_E ipv6_dst_e, Ipv6_Dst_E mask) {
        return new Ipv6_Dst_ECriterion(ipv6_dst_e, mask);
    }

    public static Criterion selectUdp_Source(long udp_source) {
        return new Udp_SourceCriterion(udp_source);
    }
  
    public static Criterion selectUdp_Source(long udp_source, long mask) {
        return new Udp_SourceCriterion(udp_source, mask);
    }

    public static Criterion selectUdp_Dest(long udp_dest) {
        return new Udp_DestCriterion(udp_dest);
    }
  
    public static Criterion selectUdp_Dest(long udp_dest, long mask) {
        return new Udp_DestCriterion(udp_dest, mask);
    }

    public static Criterion selectLen(long len) {
        return new LenCriterion(len);
    }
  
    public static Criterion selectLen(long len, long mask) {
        return new LenCriterion(len, mask);
    }

    public static Criterion selectUdp_Check(long udp_check) {
        return new Udp_CheckCriterion(udp_check);
    }
  
    public static Criterion selectUdp_Check(long udp_check, long mask) {
        return new Udp_CheckCriterion(udp_check, mask);
    }

    public static Criterion selectSrv6_Type(long srv6_type) {
        return new Srv6_TypeCriterion(srv6_type);
    }
  
    public static Criterion selectSrv6_Type(long srv6_type, long mask) {
        return new Srv6_TypeCriterion(srv6_type, mask);
    }

    public static Criterion selectSrv6_Hdr_Ext_Len(long srv6_hdr_ext_len) {
        return new Srv6_Hdr_Ext_LenCriterion(srv6_hdr_ext_len);
    }
  
    public static Criterion selectSrv6_Hdr_Ext_Len(long srv6_hdr_ext_len, long mask) {
        return new Srv6_Hdr_Ext_LenCriterion(srv6_hdr_ext_len, mask);
    }

    public static Criterion selectSrv6_Routing_Type(long srv6_routing_Type) {
        return new Srv6_Routing_TypeCriterion(srv6_routing_Type);
    }
  
    public static Criterion selectSrv6_Routing_Type(long srv6_routing_Type, long mask) {
        return new Srv6_Routing_TypeCriterion(srv6_routing_Type, mask);
    }

    public static Criterion selectSrv6_Segments_Left(long srv6_segments_left) {
        return new Srv6_Segments_LeftCriterion(srv6_segments_left);
    }
  
    public static Criterion selectSrv6_Segments_Left(long srv6_segments_left, long mask) {
        return new Srv6_Segments_LeftCriterion(srv6_segments_left, mask);
    }

    public static Criterion selectSrv6_Last_Enty(long srv6_last_enty) {
        return new Srv6_Last_EntyCriterion(srv6_last_enty);
    }
  
    public static Criterion selectSrv6_Last_Enty(long srv6_last_enty, long mask) {
        return new Srv6_Last_EntyCriterion(srv6_last_enty, mask);
    }

    public static Criterion selectSrv6_Flags(long srv6_flags) {
        return new Srv6_FlagsCriterion(srv6_flags);
    }
  
    public static Criterion selectSrv6_Flags(long srv6_flags, long mask) {
        return new Srv6_FlagsCriterion(srv6_flags, mask);
    }

    public static Criterion selectSrv6_Tag(long srv6_tag) {
        return new Srv6_TagCriterion(srv6_tag);
    }
  
    public static Criterion selectSrv6_Tag(long srv6_tag, long mask) {
        return new Srv6_TagCriterion(srv6_tag, mask);
    }

    public static Criterion selectSrv6_Segmentlist1(Srv6_Segmentlist1 srv6_segmentlist1) {
        return new Srv6_Segmentlist1Criterion(srv6_segmentlist1);
    }
  
    public static Criterion selectSrv6_Segmentlist1(Srv6_Segmentlist1 srv6_segmentlist1, Srv6_Segmentlist1 mask) {
        return new Srv6_Segmentlist1Criterion(srv6_segmentlist1, mask);
    }

    public static Criterion selectSrv6_Segmentlist2(Srv6_Segmentlist2 srv6_segmentlist2) {
        return new Srv6_Segmentlist2Criterion(srv6_segmentlist2);
    }
  
    public static Criterion selectSrv6_Segmentlist2(Srv6_Segmentlist2 srv6_segmentlist2, Srv6_Segmentlist2 mask) {
        return new Srv6_Segmentlist2Criterion(srv6_segmentlist2, mask);
    }

    public static Criterion selectSrv6_Segmentlist3(Srv6_Segmentlist3 srv6_segmentlist3) {
        return new Srv6_Segmentlist3Criterion(srv6_segmentlist3);
    }
  
    public static Criterion selectSrv6_Segmentlist3(Srv6_Segmentlist3 srv6_segmentlist3, Srv6_Segmentlist3 mask) {
        return new Srv6_Segmentlist3Criterion(srv6_segmentlist3, mask);
    }

    public static Criterion selectIpv6_Ver_Tp_Flb_I(long ipv6_ver_tp_flb_i) {
        return new Ipv6_Ver_Tp_Flb_ICriterion(ipv6_ver_tp_flb_i);
    }
  
    public static Criterion selectIpv6_Ver_Tp_Flb_I(long ipv6_ver_tp_flb_i, long mask) {
        return new Ipv6_Ver_Tp_Flb_ICriterion(ipv6_ver_tp_flb_i, mask);
    }

    public static Criterion selectIpv6_Plen_I(long ipv6_plen_i) {
        return new Ipv6_Plen_ICriterion(ipv6_plen_i);
    }
  
    public static Criterion selectIpv6_Plen_I(long ipv6_plen_i, long mask) {
        return new Ipv6_Plen_ICriterion(ipv6_plen_i, mask);
    }

    public static Criterion selectIpv6_I_Type(long ipv6_i_type) {
        return new Ipv6_I_TypeCriterion(ipv6_i_type);
    }
  
    public static Criterion selectIpv6_I_Type(long ipv6_i_type, long mask) {
        return new Ipv6_I_TypeCriterion(ipv6_i_type, mask);
    }

    public static Criterion selectIpv6_Hlmt_I(long ipv6_hlmt_i) {
        return new Ipv6_Hlmt_ICriterion(ipv6_hlmt_i);
    }
  
    public static Criterion selectIpv6_Hlmt_I(long ipv6_hlmt_i, long mask) {
        return new Ipv6_Hlmt_ICriterion(ipv6_hlmt_i, mask);
    }

    public static Criterion selectIpv6_Src_I(Ipv6_Src_I ipv6_src_i) {
        return new Ipv6_Src_ICriterion(ipv6_src_i);
    }
  
    public static Criterion selectIpv6_Src_I(Ipv6_Src_I ipv6_src_i, Ipv6_Src_I mask) {
        return new Ipv6_Src_ICriterion(ipv6_src_i, mask);
    }

    public static Criterion selectIpv6_Dst_I(Ipv6_Dst_I ipv6_dst_i) {
        return new Ipv6_Dst_ICriterion(ipv6_dst_i);
    }
  
    public static Criterion selectIpv6_Dst_I(Ipv6_Dst_I ipv6_dst_i, Ipv6_Dst_I mask) {
        return new Ipv6_Dst_ICriterion(ipv6_dst_i, mask);
    }


    /**
     * Dummy Criterion used with @see{FilteringObjective}.
     */
    private static class DummyCriterion implements Criterion {

        @Override
        public Type type() {
            return Type.DUMMY;
        }

        @Override
        public void write(ByteBuf bb){
        }

        @Override
        public void writeMask(ByteBuf bb){
        }
    }
}