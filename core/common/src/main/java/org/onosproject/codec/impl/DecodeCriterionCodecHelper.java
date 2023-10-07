/*
 * Copyright 2015-present Open Networking Foundation
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
package org.onosproject.codec.impl;

import com.esotericsoftware.kryo.io.Input;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onlab.util.HexString;
import org.onosproject.net.ChannelSpacing;
import org.onosproject.net.GridType;
import org.onosproject.net.Lambda;
import org.onosproject.net.OchSignalType;
import org.onosproject.net.OduSignalId;
import org.onosproject.net.OduSignalType;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.ExtensionCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiMatchType;
import org.onosproject.store.serializers.KryoNamespaces;
import org.slf4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.onlab.util.Tools.nullIsIllegal;
import static org.slf4j.LoggerFactory.getLogger;

import java.net.InetAddress;
import java.util.Arrays;
import java.math.BigInteger;
import java.nio.ByteBuffer;


import org.onosproject.net.flow.criteria.Mac_DstCriterion;
import org.onosproject.net.flow.criteria.Mac_SrcCriterion;
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
import org.onosproject.net.flow.criteria.Ipv6_Dst_ECriterion;
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
import org.onosproject.net.flow.criteria.Srv6_Segmentlist2Criterion;
import org.onosproject.net.flow.criteria.Srv6_Segmentlist3Criterion;
import org.onosproject.net.flow.criteria.Ipv6_Ver_Tp_Flb_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Plen_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_I_TypeCriterion;
import org.onosproject.net.flow.criteria.Ipv6_Hlmt_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Src_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Dst_ICriterion;
import org.onlab.packet.Mac_Dst;
import org.onlab.packet.Mac_Src;
import org.onlab.packet.Ipv6_Src_E;
import org.onlab.packet.Ipv6_Dst_E;
import org.onlab.packet.Srv6_Segmentlist3;
import org.onlab.packet.Srv6_Segmentlist2;
import org.onlab.packet.Srv6_Segmentlist1;
import org.onlab.packet.Ipv6_Src_I;
import org.onlab.packet.Ipv6_Dst_I;

/**
 * Decode portion of the criterion codec.
 */
public final class DecodeCriterionCodecHelper {

    private static final Logger log = getLogger(DecodeCriterionCodecHelper.class);

    private final ObjectNode json;

    protected static final String MISSING_MEMBER_MESSAGE =
            " member is required in Criterion";

    private interface CriterionDecoder {
        Criterion decodeCriterion(ObjectNode json);
    }
    private final Map<String, CriterionDecoder> decoderMap;

    /**
     * Creates a decode criterion codec object.
     * Initializes the lookup map for criterion subclass decoders.
     *
     * @param json JSON object to decode
     */
    public DecodeCriterionCodecHelper(ObjectNode json) {
        this.json = json;
        decoderMap = new HashMap<>();

    decoderMap.put(Criterion.Type.MAC_DST.name(), new Mac_DstDecoder());
    decoderMap.put(Criterion.Type.MAC_SRC.name(), new Mac_SrcDecoder());
    decoderMap.put(Criterion.Type.VLAN1_TPID.name(), new Vlan1_TpidDecoder());
    decoderMap.put(Criterion.Type.VLAN1_QID.name(), new Vlan1_QidDecoder());
    decoderMap.put(Criterion.Type.VLAN2_TPID.name(), new Vlan2_TpidDecoder());
    decoderMap.put(Criterion.Type.VLAN2_QID.name(), new Vlan2_QidDecoder());
    decoderMap.put(Criterion.Type.DL_TYPE.name(), new Dl_TypeDecoder());
    decoderMap.put(Criterion.Type.VER_HL_E.name(), new Ver_Hl_EDecoder());
    decoderMap.put(Criterion.Type.TOS_E.name(), new Tos_EDecoder());
    decoderMap.put(Criterion.Type.TOT_LEN_E.name(), new Tot_Len_EDecoder());
    decoderMap.put(Criterion.Type.IP_ID_E.name(), new Ip_Id_EDecoder());
    decoderMap.put(Criterion.Type.FRAG_OFF_E.name(), new Frag_Off_EDecoder());
    decoderMap.put(Criterion.Type.TTL_E.name(), new Ttl_EDecoder());
    decoderMap.put(Criterion.Type.IPV4_E_TYPE.name(), new Ipv4_E_TypeDecoder());
    decoderMap.put(Criterion.Type.IP_CHECK_E.name(), new Ip_Check_EDecoder());
    decoderMap.put(Criterion.Type.IP_SADDR_E.name(), new Ip_Saddr_EDecoder());
    decoderMap.put(Criterion.Type.IP_DADDR_E.name(), new Ip_Daddr_EDecoder());
    decoderMap.put(Criterion.Type.IPV6_VER_TP_FLB_E.name(), new Ipv6_Ver_Tp_Flb_EDecoder());
    decoderMap.put(Criterion.Type.IPV6_PLEN_E.name(), new Ipv6_Plen_EDecoder());
    decoderMap.put(Criterion.Type.IPV6_E_TYPE.name(), new Ipv6_E_TypeDecoder());
    decoderMap.put(Criterion.Type.IPV6_HLMT_E.name(), new Ipv6_Hlmt_EDecoder());
    decoderMap.put(Criterion.Type.IPV6_SRC_E.name(), new Ipv6_Src_EDecoder());
    decoderMap.put(Criterion.Type.IPV6_DST_E.name(), new Ipv6_Dst_EDecoder());
    decoderMap.put(Criterion.Type.UDP_SOURCE.name(), new Udp_SourceDecoder());
    decoderMap.put(Criterion.Type.UDP_DEST.name(), new Udp_DestDecoder());
    decoderMap.put(Criterion.Type.LEN.name(), new LenDecoder());
    decoderMap.put(Criterion.Type.UDP_CHECK.name(), new Udp_CheckDecoder());
    decoderMap.put(Criterion.Type.SRV6_TYPE.name(), new Srv6_TypeDecoder());
    decoderMap.put(Criterion.Type.SRV6_HDR_EXT_LEN.name(), new Srv6_Hdr_Ext_LenDecoder());
    decoderMap.put(Criterion.Type.SRV6_ROUTING_TYPE.name(), new Srv6_Routing_TypeDecoder());
    decoderMap.put(Criterion.Type.SRV6_SEGMENTS_LEFT.name(), new Srv6_Segments_LeftDecoder());
    decoderMap.put(Criterion.Type.SRV6_LAST_ENTY.name(), new Srv6_Last_EntyDecoder());
    decoderMap.put(Criterion.Type.SRV6_FLAGS.name(), new Srv6_FlagsDecoder());
    decoderMap.put(Criterion.Type.SRV6_TAG.name(), new Srv6_TagDecoder());
    decoderMap.put(Criterion.Type.SRV6_SEGMENTLIST3.name(), new Srv6_Segmentlist3Decoder());
    decoderMap.put(Criterion.Type.SRV6_SEGMENTLIST2.name(), new Srv6_Segmentlist2Decoder());
    decoderMap.put(Criterion.Type.SRV6_SEGMENTLIST1.name(), new Srv6_Segmentlist1Decoder());
    decoderMap.put(Criterion.Type.IPV6_VER_TP_FLB_I.name(), new Ipv6_Ver_Tp_Flb_IDecoder());
    decoderMap.put(Criterion.Type.IPV6_PLEN_I.name(), new Ipv6_Plen_IDecoder());
    decoderMap.put(Criterion.Type.IPV6_I_TYPE.name(), new Ipv6_I_TypeDecoder());
    decoderMap.put(Criterion.Type.IPV6_HLMT_I.name(), new Ipv6_Hlmt_IDecoder());
    decoderMap.put(Criterion.Type.IPV6_SRC_I.name(), new Ipv6_Src_IDecoder());
    decoderMap.put(Criterion.Type.IPV6_DST_I.name(), new Ipv6_Dst_IDecoder());
    }

    private class EthTypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode ethTypeNode = nullIsIllegal(json.get(CriterionCodec.ETH_TYPE),
                                              CriterionCodec.ETH_TYPE + MISSING_MEMBER_MESSAGE);
            int ethType;
            if (ethTypeNode.isInt()) {
                ethType = ethTypeNode.asInt();
            } else {
                ethType = Integer.decode(ethTypeNode.textValue());
            }
            return Criteria.matchEthType(ethType);
        }
    }

    private class EthDstDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            MacAddress mac = MacAddress.valueOf(nullIsIllegal(json.get(CriterionCodec.MAC),
                    CriterionCodec.MAC + MISSING_MEMBER_MESSAGE).asText());

            return Criteria.matchEthDst(mac);
        }
    }

    private class EthDstMaskedDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            MacAddress mac = MacAddress.valueOf(nullIsIllegal(json.get(CriterionCodec.MAC),
                    CriterionCodec.MAC + MISSING_MEMBER_MESSAGE).asText());
            MacAddress macMask = MacAddress.valueOf(nullIsIllegal(json.get(CriterionCodec.MAC_MASK),
                    CriterionCodec.MAC_MASK + MISSING_MEMBER_MESSAGE).asText());
            return Criteria.matchEthDstMasked(mac, macMask);
        }
    }

    private class EthSrcDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            MacAddress mac = MacAddress.valueOf(nullIsIllegal(json.get(CriterionCodec.MAC),
                    CriterionCodec.MAC + MISSING_MEMBER_MESSAGE).asText());

            return Criteria.matchEthSrc(mac);
        }
    }

    private class EthSrcMaskedDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            MacAddress mac = MacAddress.valueOf(nullIsIllegal(json.get(CriterionCodec.MAC),
                    CriterionCodec.MAC + MISSING_MEMBER_MESSAGE).asText());
            MacAddress macMask = MacAddress.valueOf(nullIsIllegal(json.get(CriterionCodec.MAC_MASK),
                    CriterionCodec.MAC_MASK + MISSING_MEMBER_MESSAGE).asText());
            return Criteria.matchEthSrcMasked(mac, macMask);
        }
    }

    private class InPortDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            PortNumber port = PortNumber.portNumber(nullIsIllegal(json.get(CriterionCodec.PORT),
                                                                  CriterionCodec.PORT +
                                                                          MISSING_MEMBER_MESSAGE).asLong());

            return Criteria.matchInPort(port);
        }
    }

    private class InPhyPortDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            PortNumber port = PortNumber.portNumber(nullIsIllegal(json.get(CriterionCodec.PORT),
                                                                  CriterionCodec.PORT +
                                                                          MISSING_MEMBER_MESSAGE).asLong());

            return Criteria.matchInPhyPort(port);
        }
    }

    private class MetadataDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            long metadata = nullIsIllegal(json.get(CriterionCodec.METADATA),
                    CriterionCodec.METADATA + MISSING_MEMBER_MESSAGE).asLong();

            return Criteria.matchMetadata(metadata);
        }
    }

    private class VlanVidDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            short vlanId = (short) nullIsIllegal(json.get(CriterionCodec.VLAN_ID),
                    CriterionCodec.VLAN_ID + MISSING_MEMBER_MESSAGE).asInt();

            return Criteria.matchVlanId(VlanId.vlanId(vlanId));
        }
    }

    private class VlanPcpDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            byte priority = (byte) nullIsIllegal(json.get(CriterionCodec.PRIORITY),
                    CriterionCodec.PRIORITY + MISSING_MEMBER_MESSAGE).asInt();

            return Criteria.matchVlanPcp(priority);
        }
    }

    private class InnerVlanVidDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            short vlanId = (short) nullIsIllegal(json.get(CriterionCodec.INNER_VLAN_ID),
                                                 CriterionCodec.INNER_VLAN_ID +
                                                         MISSING_MEMBER_MESSAGE).asInt();

            return Criteria.matchInnerVlanId(VlanId.vlanId(vlanId));
        }
    }

    private class InnerVlanPcpDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            byte priority = (byte) nullIsIllegal(json.get(CriterionCodec.INNER_PRIORITY),
                                                 CriterionCodec.INNER_PRIORITY +
                                                         MISSING_MEMBER_MESSAGE).asInt();

            return Criteria.matchInnerVlanPcp(priority);
        }
    }

    private class IpDscpDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            byte ipDscp = (byte) nullIsIllegal(json.get(CriterionCodec.IP_DSCP),
                    CriterionCodec.IP_DSCP + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchIPDscp(ipDscp);
        }
    }

    private class IpEcnDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            byte ipEcn = (byte) nullIsIllegal(json.get(CriterionCodec.IP_ECN),
                    CriterionCodec.IP_ECN + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchIPEcn(ipEcn);
        }
    }

    private class IpProtoDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            short proto = (short) nullIsIllegal(json.get(CriterionCodec.PROTOCOL),
                    CriterionCodec.PROTOCOL + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchIPProtocol(proto);
        }
    }

    private class IpV4SrcDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String ip = nullIsIllegal(json.get(CriterionCodec.IP),
                    CriterionCodec.IP + MISSING_MEMBER_MESSAGE).asText();
            return Criteria.matchIPSrc(IpPrefix.valueOf(ip));
        }
    }

    private class IpV4DstDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String ip = nullIsIllegal(json.get(CriterionCodec.IP),
                    CriterionCodec.IP + MISSING_MEMBER_MESSAGE).asText();
            return Criteria.matchIPDst(IpPrefix.valueOf(ip));
        }
    }

    private class IpV6SrcDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String ip = nullIsIllegal(json.get(CriterionCodec.IP),
                    CriterionCodec.IP + MISSING_MEMBER_MESSAGE).asText();
            return Criteria.matchIPv6Src(IpPrefix.valueOf(ip));
        }
    }

    private class IpV6DstDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String ip = nullIsIllegal(json.get(CriterionCodec.IP),
                    CriterionCodec.IP + MISSING_MEMBER_MESSAGE).asText();
            return Criteria.matchIPv6Dst(IpPrefix.valueOf(ip));
        }
    }

    private class TcpSrcDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort tcpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.TCP_PORT),
                    CriterionCodec.TCP_PORT + MISSING_MEMBER_MESSAGE).asInt());
            return Criteria.matchTcpSrc(tcpPort);
        }
    }

    private class TcpSrcMaskDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort tcpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.TCP_PORT),
                    CriterionCodec.TCP_PORT + MISSING_MEMBER_MESSAGE).asInt());

            TpPort tcpMask = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.TCP_MASK),
                    CriterionCodec.TCP_MASK + MISSING_MEMBER_MESSAGE).asInt());

            return Criteria.matchTcpSrcMasked(tcpPort, tcpMask);
        }
    }

    private class TcpDstDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort tcpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.TCP_PORT),
                    CriterionCodec.TCP_PORT + MISSING_MEMBER_MESSAGE).asInt());
            return Criteria.matchTcpDst(tcpPort);
        }
    }

    private class TcpDstMaskDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort tcpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.TCP_PORT),
                    CriterionCodec.TCP_PORT + MISSING_MEMBER_MESSAGE).asInt());

            TpPort tcpMask = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.TCP_MASK),
                    CriterionCodec.TCP_MASK + MISSING_MEMBER_MESSAGE).asInt());

            return Criteria.matchTcpDstMasked(tcpPort, tcpMask);
        }
    }

    private class UdpSrcDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort udpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.UDP_PORT),
                    CriterionCodec.UDP_PORT + MISSING_MEMBER_MESSAGE).asInt());
            return Criteria.matchUdpSrc(udpPort);
        }
    }

    private class UdpSrcMaskDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort udpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.UDP_PORT),
                    CriterionCodec.UDP_PORT + MISSING_MEMBER_MESSAGE).asInt());

            TpPort udpMask = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.UDP_MASK),
                    CriterionCodec.UDP_MASK + MISSING_MEMBER_MESSAGE).asInt());

            return Criteria.matchUdpSrcMasked(udpPort, udpMask);
        }
    }

    private class UdpDstDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort udpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.UDP_PORT),
                    CriterionCodec.UDP_PORT + MISSING_MEMBER_MESSAGE).asInt());
            return Criteria.matchUdpDst(udpPort);
        }
    }

    private class UdpDstMaskDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort udpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.UDP_PORT),
                    CriterionCodec.UDP_PORT + MISSING_MEMBER_MESSAGE).asInt());

            TpPort udpMask = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.UDP_MASK),
                    CriterionCodec.UDP_MASK + MISSING_MEMBER_MESSAGE).asInt());

            return Criteria.matchUdpDstMasked(udpPort, udpMask);
        }
    }

    private class SctpSrcDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort sctpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.SCTP_PORT),
                    CriterionCodec.SCTP_PORT + MISSING_MEMBER_MESSAGE).asInt());
            return Criteria.matchSctpSrc(sctpPort);
        }
    }

    private class SctpSrcMaskDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort sctpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.SCTP_PORT),
                    CriterionCodec.SCTP_PORT + MISSING_MEMBER_MESSAGE).asInt());

            TpPort sctpMask = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.SCTP_MASK),
                    CriterionCodec.SCTP_MASK + MISSING_MEMBER_MESSAGE).asInt());

            return Criteria.matchSctpSrcMasked(sctpPort, sctpMask);
        }
    }

    private class SctpDstDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort sctpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.SCTP_PORT),
                    CriterionCodec.SCTP_PORT + MISSING_MEMBER_MESSAGE).asInt());
            return Criteria.matchSctpDst(sctpPort);
        }
    }

    private class SctpDstMaskDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            TpPort sctpPort = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.SCTP_PORT),
                    CriterionCodec.SCTP_PORT + MISSING_MEMBER_MESSAGE).asInt());

            TpPort sctpMask = TpPort.tpPort(nullIsIllegal(json.get(CriterionCodec.SCTP_MASK),
                    CriterionCodec.SCTP_MASK + MISSING_MEMBER_MESSAGE).asInt());

            return Criteria.matchSctpDstMasked(sctpPort, sctpMask);
        }
    }

    private class IcmpV4TypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            short type = (short) nullIsIllegal(json.get(CriterionCodec.ICMP_TYPE),
                    CriterionCodec.ICMP_TYPE + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchIcmpType(type);
        }
    }

    private class IcmpV4CodeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            short code = (short) nullIsIllegal(json.get(CriterionCodec.ICMP_CODE),
                    CriterionCodec.ICMP_CODE + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchIcmpCode(code);
        }
    }

    private class IpV6FLabelDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            int flowLabel = nullIsIllegal(json.get(CriterionCodec.FLOW_LABEL),
                    CriterionCodec.FLOW_LABEL + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchIPv6FlowLabel(flowLabel);
        }
    }

    private class IcmpV6TypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            short type = (short) nullIsIllegal(json.get(CriterionCodec.ICMPV6_TYPE),
                    CriterionCodec.ICMPV6_TYPE + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchIcmpv6Type(type);
        }
    }

    private class IcmpV6CodeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            short code = (short) nullIsIllegal(json.get(CriterionCodec.ICMPV6_CODE),
                    CriterionCodec.ICMPV6_CODE + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchIcmpv6Code(code);
        }
    }

    private class V6NDTargetDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            Ip6Address target = Ip6Address.valueOf(nullIsIllegal(json.get(CriterionCodec.TARGET_ADDRESS),
                    CriterionCodec.TARGET_ADDRESS + MISSING_MEMBER_MESSAGE).asText());
            return Criteria.matchIPv6NDTargetAddress(target);
        }
    }

    private class V6NDSllDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            MacAddress mac = MacAddress.valueOf(nullIsIllegal(json.get(CriterionCodec.MAC),
                    CriterionCodec.MAC + MISSING_MEMBER_MESSAGE).asText());
            return Criteria.matchIPv6NDSourceLinkLayerAddress(mac);
        }
    }

    private class V6NDTllDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            MacAddress mac = MacAddress.valueOf(nullIsIllegal(json.get(CriterionCodec.MAC),
                    CriterionCodec.MAC + MISSING_MEMBER_MESSAGE).asText());
            return Criteria.matchIPv6NDTargetLinkLayerAddress(mac);
        }
    }

    private class MplsLabelDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            int label = nullIsIllegal(json.get(CriterionCodec.LABEL),
                    CriterionCodec.LABEL + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchMplsLabel(MplsLabel.mplsLabel(label));
        }
    }

    private class MplsBosDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            boolean bos = nullIsIllegal(json.get(CriterionCodec.BOS),
                    CriterionCodec.BOS + MISSING_MEMBER_MESSAGE).asBoolean();
            return Criteria.matchMplsBos(bos);
        }
    }

    private class IpV6ExthdrDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            int exthdrFlags = nullIsIllegal(json.get(CriterionCodec.EXT_HDR_FLAGS),
                    CriterionCodec.EXT_HDR_FLAGS + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchIPv6ExthdrFlags(exthdrFlags);
        }
    }

    private class OchSigIdDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode ochSignalId = nullIsIllegal(json.get(CriterionCodec.OCH_SIGNAL_ID),
                    CriterionCodec.GRID_TYPE + MISSING_MEMBER_MESSAGE);
            GridType gridType =
                    GridType.valueOf(
                            nullIsIllegal(ochSignalId.get(CriterionCodec.GRID_TYPE),
                            CriterionCodec.GRID_TYPE + MISSING_MEMBER_MESSAGE).asText());
            ChannelSpacing channelSpacing =
                    ChannelSpacing.valueOf(
                            nullIsIllegal(ochSignalId.get(CriterionCodec.CHANNEL_SPACING),
                            CriterionCodec.CHANNEL_SPACING + MISSING_MEMBER_MESSAGE).asText());
            int spacingMultiplier = nullIsIllegal(ochSignalId.get(CriterionCodec.SPACING_MULIPLIER),
                    CriterionCodec.SPACING_MULIPLIER + MISSING_MEMBER_MESSAGE).asInt();
            int slotGranularity = nullIsIllegal(ochSignalId.get(CriterionCodec.SLOT_GRANULARITY),
                    CriterionCodec.SLOT_GRANULARITY + MISSING_MEMBER_MESSAGE).asInt();
            return Criteria.matchLambda(
                    Lambda.ochSignal(gridType, channelSpacing,
                            spacingMultiplier, slotGranularity));
        }
    }

    private class OchSigTypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            OchSignalType ochSignalType = OchSignalType.valueOf(nullIsIllegal(json.get(CriterionCodec.OCH_SIGNAL_TYPE),
                    CriterionCodec.OCH_SIGNAL_TYPE + MISSING_MEMBER_MESSAGE).asText());
            return Criteria.matchOchSignalType(ochSignalType);
        }
    }

    private class TunnelIdDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            long tunnelId = nullIsIllegal(json.get(CriterionCodec.TUNNEL_ID),
                    CriterionCodec.TUNNEL_ID + MISSING_MEMBER_MESSAGE).asLong();
            return Criteria.matchTunnelId(tunnelId);
        }
    }

    private class OduSigIdDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode oduSignalId = nullIsIllegal(json.get(CriterionCodec.ODU_SIGNAL_ID),
                    CriterionCodec.TRIBUTARY_PORT_NUMBER + MISSING_MEMBER_MESSAGE);

            int tributaryPortNumber = nullIsIllegal(oduSignalId.get(CriterionCodec.TRIBUTARY_PORT_NUMBER),
                    CriterionCodec.TRIBUTARY_PORT_NUMBER + MISSING_MEMBER_MESSAGE).asInt();
            int tributarySlotLen = nullIsIllegal(oduSignalId.get(CriterionCodec.TRIBUTARY_SLOT_LEN),
                    CriterionCodec.TRIBUTARY_SLOT_LEN + MISSING_MEMBER_MESSAGE).asInt();
            byte[] tributarySlotBitmap = HexString.fromHexString(
                    nullIsIllegal(oduSignalId.get(CriterionCodec.TRIBUTARY_SLOT_BITMAP),
                    CriterionCodec.TRIBUTARY_SLOT_BITMAP + MISSING_MEMBER_MESSAGE).asText());

            return Criteria.matchOduSignalId(
                    OduSignalId.oduSignalId(tributaryPortNumber, tributarySlotLen, tributarySlotBitmap));
        }
    }

    private class OduSigTypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            OduSignalType oduSignalType = OduSignalType.valueOf(nullIsIllegal(json.get(CriterionCodec.ODU_SIGNAL_TYPE),
                    CriterionCodec.ODU_SIGNAL_TYPE + MISSING_MEMBER_MESSAGE).asText());
            return Criteria.matchOduSignalType(oduSignalType);
        }
    }

    private class PiDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            PiCriterion.Builder builder = PiCriterion.builder();
            JsonNode matchesNode = nullIsIllegal(json.get(CriterionCodec.PI_MATCHES),
                                                 CriterionCodec.PI_MATCHES + MISSING_MEMBER_MESSAGE);
            if (matchesNode.isArray()) {
                for (JsonNode node : matchesNode) {
                    String type = nullIsIllegal(node.get(CriterionCodec.PI_MATCH_TYPE),
                                                CriterionCodec.PI_MATCH_TYPE + MISSING_MEMBER_MESSAGE).asText();
                    switch (PiMatchType.valueOf(type.toUpperCase())) {
                        case EXACT:
                            builder.matchExact(
                                    PiMatchFieldId.of(
                                            nullIsIllegal(node.get(CriterionCodec.PI_MATCH_FIELD_ID),
                                                          CriterionCodec.PI_MATCH_FIELD_ID +
                                                                  MISSING_MEMBER_MESSAGE).asText()),
                                    HexString.fromHexString(nullIsIllegal(node.get(CriterionCodec.PI_MATCH_VALUE),
                                                                    CriterionCodec.PI_MATCH_VALUE +
                                                                            MISSING_MEMBER_MESSAGE).asText(), null));
                            break;
                        case LPM:
                            builder.matchLpm(
                                    PiMatchFieldId.of(
                                            nullIsIllegal(node.get(CriterionCodec.PI_MATCH_FIELD_ID),
                                                          CriterionCodec.PI_MATCH_FIELD_ID +
                                                                  MISSING_MEMBER_MESSAGE).asText()),
                                    HexString.fromHexString(nullIsIllegal(node.get(CriterionCodec.PI_MATCH_VALUE),
                                                                    CriterionCodec.PI_MATCH_VALUE +
                                                                            MISSING_MEMBER_MESSAGE).asText(), null),
                                    nullIsIllegal(node.get(CriterionCodec.PI_MATCH_PREFIX),
                                                  CriterionCodec.PI_MATCH_PREFIX +
                                                          MISSING_MEMBER_MESSAGE).asInt());
                            break;
                        case TERNARY:
                            builder.matchTernary(
                                    PiMatchFieldId.of(
                                            nullIsIllegal(node.get(CriterionCodec.PI_MATCH_FIELD_ID),
                                                          CriterionCodec.PI_MATCH_FIELD_ID +
                                                                  MISSING_MEMBER_MESSAGE).asText()),
                                    HexString.fromHexString(nullIsIllegal(node.get(CriterionCodec.PI_MATCH_VALUE),
                                                                    CriterionCodec.PI_MATCH_VALUE +
                                                                            MISSING_MEMBER_MESSAGE).asText(), null),
                                    HexString.fromHexString(nullIsIllegal(node.get(CriterionCodec.PI_MATCH_MASK),
                                                                    CriterionCodec.PI_MATCH_MASK +
                                                                            MISSING_MEMBER_MESSAGE).asText(), null));
                            break;
                        case RANGE:
                            builder.matchRange(
                                    PiMatchFieldId.of(
                                            nullIsIllegal(node.get(CriterionCodec.PI_MATCH_FIELD_ID),
                                                          CriterionCodec.PI_MATCH_FIELD_ID +
                                                                  MISSING_MEMBER_MESSAGE).asText()),
                                    HexString.fromHexString(nullIsIllegal(node.get(CriterionCodec.PI_MATCH_LOW_VALUE),
                                                                    CriterionCodec.PI_MATCH_LOW_VALUE +
                                                                            MISSING_MEMBER_MESSAGE).asText(), null),
                                    HexString.fromHexString(nullIsIllegal(node.get(CriterionCodec.PI_MATCH_HIGH_VALUE),
                                                                     CriterionCodec.PI_MATCH_HIGH_VALUE +
                                                                             MISSING_MEMBER_MESSAGE).asText(), null));
                            break;
                        case OPTIONAL:
                            builder.matchOptional(
                                    PiMatchFieldId.of(
                                            nullIsIllegal(node.get(CriterionCodec.PI_MATCH_FIELD_ID),
                                                          CriterionCodec.PI_MATCH_FIELD_ID +
                                                                  MISSING_MEMBER_MESSAGE).asText()),
                                    HexString.fromHexString(nullIsIllegal(node.get(CriterionCodec.PI_MATCH_VALUE),
                                                                    CriterionCodec.PI_MATCH_VALUE +
                                                                            MISSING_MEMBER_MESSAGE).asText(), null));
                            break;
                        default:
                            throw new IllegalArgumentException("Type " + type + " is unsupported");
                    }
                }
            } else {
                throw new IllegalArgumentException("Protocol-independent matches must be in an array.");
            }

            return builder.build();
        }
    }

    private class ExtensionDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            try {
                byte[] buffer = nullIsIllegal(json.get(CriterionCodec.EXTENSION),
                        CriterionCodec.EXTENSION + MISSING_MEMBER_MESSAGE).binaryValue();
                Input input = new Input(new ByteArrayInputStream(buffer));
                ExtensionCriterion extensionCriterion =
                        KryoNamespaces.API.borrow().readObject(input, ExtensionCriterion.class);
                input.close();
                return extensionCriterion;
            } catch (IOException e) {
                log.warn("Cannot convert the {} field into byte array", CriterionCodec.EXTENSION);
                return null;
            }
        }
    }

    /**
     * Decodes the JSON into a criterion object.
     *
     * @return Criterion object
     * @throws IllegalArgumentException if the JSON is invalid
     */
    public Criterion decode() {
        String type =
                nullIsIllegal(json.get(CriterionCodec.TYPE), "Type not specified")
                        .asText();

        CriterionDecoder decoder = decoderMap.get(type);
        if (decoder != null) {
            return decoder.decodeCriterion(json);
        }

        throw new IllegalArgumentException("Type " + type + " is unknown");
    }

private class Mac_DstDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      byte[] data = macAddressToByteArray(nullIsIllegal(json.get(CriterionCodec.MAC_DST),
                    CriterionCodec.MAC_DST + MISSING_MEMBER_MESSAGE).asText());
      
      Mac_Dst dst = Mac_Dst.valueOf(data);
      
      return Criteria.selectMac_Dst(dst);
    }
}

private class Mac_SrcDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      byte[] data = macAddressToByteArray(nullIsIllegal(json.get(CriterionCodec.MAC_SRC),
                    CriterionCodec.MAC_SRC + MISSING_MEMBER_MESSAGE).asText());
      
      Mac_Src dst = Mac_Src.valueOf(data);
      
      return Criteria.selectMac_Src(dst);
    }
}

private class Vlan1_TpidDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VLAN1_TPID),
                                      CriterionCodec.VLAN1_TPID + MISSING_MEMBER_MESSAGE);
      	
      	short vlan1_tpid;
        if (Node.isInt()) {
            vlan1_tpid = (short)Node.asInt();
        } else {
            vlan1_tpid = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectVlan1_Tpid(vlan1_tpid);
    }
}

private class Vlan1_QidDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VLAN1_QID),
                                      CriterionCodec.VLAN1_QID + MISSING_MEMBER_MESSAGE);
      	
      	short vlan1_qid;
        if (Node.isInt()) {
            vlan1_qid = (short)Node.asInt();
        } else {
            vlan1_qid = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectVlan1_Qid(vlan1_qid);
    }
}

private class Vlan2_TpidDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VLAN2_TPID),
                                      CriterionCodec.VLAN2_TPID + MISSING_MEMBER_MESSAGE);
      	
      	short vlan2_tpid;
        if (Node.isInt()) {
            vlan2_tpid = (short)Node.asInt();
        } else {
            vlan2_tpid = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectVlan2_Tpid(vlan2_tpid);
    }
}

private class Vlan2_QidDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VLAN2_QID),
                                      CriterionCodec.VLAN2_QID + MISSING_MEMBER_MESSAGE);
      	
      	short vlan2_qid;
        if (Node.isInt()) {
            vlan2_qid = (short)Node.asInt();
        } else {
            vlan2_qid = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectVlan2_Qid(vlan2_qid);
    }
}

private class Dl_TypeDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.DL_TYPE),
                                      CriterionCodec.DL_TYPE + MISSING_MEMBER_MESSAGE);
      	
      	short dl_type;
        if (Node.isInt()) {
            dl_type = (short)Node.asInt();
        } else {
            dl_type = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectDl_Type(dl_type);
    }
}

private class Ver_Hl_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VER_HL_E),
                                      CriterionCodec.VER_HL_E + MISSING_MEMBER_MESSAGE);
      	
      	byte ver_hl_e;
        if (Node.isInt()) {
            ver_hl_e = (byte)Node.asInt();
        } else {
            ver_hl_e = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectVer_Hl_E(ver_hl_e);
    }
}

private class Tos_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TOS_E),
                                      CriterionCodec.TOS_E + MISSING_MEMBER_MESSAGE);
      	
      	byte tos_e;
        if (Node.isInt()) {
            tos_e = (byte)Node.asInt();
        } else {
            tos_e = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectTos_E(tos_e);
    }
}

private class Tot_Len_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TOT_LEN_E),
                                      CriterionCodec.TOT_LEN_E + MISSING_MEMBER_MESSAGE);
      	
      	short tot_len_e;
        if (Node.isInt()) {
            tot_len_e = (short)Node.asInt();
        } else {
            tot_len_e = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectTot_Len_E(tot_len_e);
    }
}

private class Ip_Id_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_ID_E),
                                      CriterionCodec.IP_ID_E + MISSING_MEMBER_MESSAGE);
      	
      	short ip_id_e;
        if (Node.isInt()) {
            ip_id_e = (short)Node.asInt();
        } else {
            ip_id_e = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectIp_Id_E(ip_id_e);
    }
}

private class Frag_Off_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.FRAG_OFF_E),
                                      CriterionCodec.FRAG_OFF_E + MISSING_MEMBER_MESSAGE);
      	
      	short frag_off_e;
        if (Node.isInt()) {
            frag_off_e = (short)Node.asInt();
        } else {
            frag_off_e = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectFrag_Off_E(frag_off_e);
    }
}

private class Ttl_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TTL_E),
                                      CriterionCodec.TTL_E + MISSING_MEMBER_MESSAGE);
      	
      	byte ttl_e;
        if (Node.isInt()) {
            ttl_e = (byte)Node.asInt();
        } else {
            ttl_e = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectTtl_E(ttl_e);
    }
}

private class Ipv4_E_TypeDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV4_E_TYPE),
                                      CriterionCodec.IPV4_E_TYPE + MISSING_MEMBER_MESSAGE);
      	
      	byte ipv4_e_type;
        if (Node.isInt()) {
            ipv4_e_type = (byte)Node.asInt();
        } else {
            ipv4_e_type = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectIpv4_E_Type(ipv4_e_type);
    }
}

private class Ip_Check_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_CHECK_E),
                                      CriterionCodec.IP_CHECK_E + MISSING_MEMBER_MESSAGE);
      	
      	short ip_check_e;
        if (Node.isInt()) {
            ip_check_e = (short)Node.asInt();
        } else {
            ip_check_e = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectIp_Check_E(ip_check_e);
    }
}

private class Ip_Saddr_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      if(Ip_Saddr_ECriterion.LEN != 4){
        throw new IllegalArgumentException("Invalid ipv4 address format.");
      }
      byte[] data = new byte[Ip_Saddr_ECriterion.LEN];
      byte[] mask = new byte[Ip_Saddr_ECriterion.LEN];
      
      parseIpAddress(nullIsIllegal(json.get(CriterionCodec.IP_SADDR_E),
                    CriterionCodec.IP_SADDR_E + MISSING_MEMBER_MESSAGE).asText(), data, mask);
      
      return Criteria.selectIp_Saddr_E(ByteBuffer.wrap(data).getInt(), ByteBuffer.wrap(mask).getInt());
    }
}

private class Ip_Daddr_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      if(Ip_Daddr_ECriterion.LEN != 4){
        throw new IllegalArgumentException("Invalid ipv4 address format.");
      }
      byte[] data = new byte[Ip_Daddr_ECriterion.LEN];
      byte[] mask = new byte[Ip_Daddr_ECriterion.LEN];
      
      parseIpAddress(nullIsIllegal(json.get(CriterionCodec.IP_DADDR_E),
                    CriterionCodec.IP_DADDR_E + MISSING_MEMBER_MESSAGE).asText(), data, mask);
      
      return Criteria.selectIp_Daddr_E(ByteBuffer.wrap(data).getInt(), ByteBuffer.wrap(mask).getInt());
    }
}

private class Ipv6_Ver_Tp_Flb_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_VER_TP_FLB_E),
                                      CriterionCodec.IPV6_VER_TP_FLB_E + MISSING_MEMBER_MESSAGE);
      	
      	int ipv6_ver_tp_flb_e;
        if (Node.isInt()) {
            ipv6_ver_tp_flb_e = Node.asInt();
        } else {
            ipv6_ver_tp_flb_e = Integer.decode(Node.textValue());
        }
      
        return Criteria.selectIpv6_Ver_Tp_Flb_E(ipv6_ver_tp_flb_e);
    }
}

private class Ipv6_Plen_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_PLEN_E),
                                      CriterionCodec.IPV6_PLEN_E + MISSING_MEMBER_MESSAGE);
      	
      	short ipv6_plen_e;
        if (Node.isInt()) {
            ipv6_plen_e = (short)Node.asInt();
        } else {
            ipv6_plen_e = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectIpv6_Plen_E(ipv6_plen_e);
    }
}

private class Ipv6_E_TypeDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_E_TYPE),
                                      CriterionCodec.IPV6_E_TYPE + MISSING_MEMBER_MESSAGE);
      	
      	byte ipv6_e_type;
        if (Node.isInt()) {
            ipv6_e_type = (byte)Node.asInt();
        } else {
            ipv6_e_type = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectIpv6_E_Type(ipv6_e_type);
    }
}

private class Ipv6_Hlmt_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_HLMT_E),
                                      CriterionCodec.IPV6_HLMT_E + MISSING_MEMBER_MESSAGE);
      	
      	byte ipv6_hlmt_e;
        if (Node.isInt()) {
            ipv6_hlmt_e = (byte)Node.asInt();
        } else {
            ipv6_hlmt_e = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectIpv6_Hlmt_E(ipv6_hlmt_e);
    }
}

private class Ipv6_Src_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      byte[] data = new byte[Ipv6_Src_E.LEN];
      byte[] mask = new byte[Ipv6_Src_E.LEN];
      
      parseIpAddress(nullIsIllegal(json.get(CriterionCodec.IPV6_SRC_E),
                    CriterionCodec.IPV6_SRC_E + MISSING_MEMBER_MESSAGE).asText(), data, mask);
      
      Ipv6_Src_E IPData = Ipv6_Src_E.valueOf(data);
      Ipv6_Src_E IPMask = Ipv6_Src_E.valueOf(mask);
      return Criteria.selectIpv6_Src_E(IPData, IPMask);
    }
}

private class Ipv6_Dst_EDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      byte[] data = new byte[Ipv6_Dst_E.LEN];
      byte[] mask = new byte[Ipv6_Dst_E.LEN];
      
      parseIpAddress(nullIsIllegal(json.get(CriterionCodec.IPV6_DST_E),
                    CriterionCodec.IPV6_DST_E + MISSING_MEMBER_MESSAGE).asText(), data, mask);
      
      Ipv6_Dst_E IPData = Ipv6_Dst_E.valueOf(data);
      Ipv6_Dst_E IPMask = Ipv6_Dst_E.valueOf(mask);
      return Criteria.selectIpv6_Dst_E(IPData, IPMask);
    }
}

private class Udp_SourceDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.UDP_SOURCE),
                                      CriterionCodec.UDP_SOURCE + MISSING_MEMBER_MESSAGE);
      	
      	short udp_source;
        if (Node.isInt()) {
            udp_source = (short)Node.asInt();
        } else {
            udp_source = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectUdp_Source(udp_source);
    }
}

private class Udp_DestDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.UDP_DEST),
                                      CriterionCodec.UDP_DEST + MISSING_MEMBER_MESSAGE);
      	
      	short udp_dest;
        if (Node.isInt()) {
            udp_dest = (short)Node.asInt();
        } else {
            udp_dest = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectUdp_Dest(udp_dest);
    }
}

private class LenDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.LEN),
                                      CriterionCodec.LEN + MISSING_MEMBER_MESSAGE);
      	
      	short len;
        if (Node.isInt()) {
            len = (short)Node.asInt();
        } else {
            len = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectLen(len);
    }
}

private class Udp_CheckDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.UDP_CHECK),
                                      CriterionCodec.UDP_CHECK + MISSING_MEMBER_MESSAGE);
      	
      	short udp_check;
        if (Node.isInt()) {
            udp_check = (short)Node.asInt();
        } else {
            udp_check = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectUdp_Check(udp_check);
    }
}

private class Srv6_TypeDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_TYPE),
                                      CriterionCodec.SRV6_TYPE + MISSING_MEMBER_MESSAGE);
      	
      	byte srv6_type;
        if (Node.isInt()) {
            srv6_type = (byte)Node.asInt();
        } else {
            srv6_type = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectSrv6_Type(srv6_type);
    }
}

private class Srv6_Hdr_Ext_LenDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_HDR_EXT_LEN),
                                      CriterionCodec.SRV6_HDR_EXT_LEN + MISSING_MEMBER_MESSAGE);
      	
      	byte srv6_hdr_ext_len;
        if (Node.isInt()) {
            srv6_hdr_ext_len = (byte)Node.asInt();
        } else {
            srv6_hdr_ext_len = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectSrv6_Hdr_Ext_Len(srv6_hdr_ext_len);
    }
}

private class Srv6_Routing_TypeDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_ROUTING_TYPE),
                                      CriterionCodec.SRV6_ROUTING_TYPE + MISSING_MEMBER_MESSAGE);
      	
      	byte srv6_routing_Type;
        if (Node.isInt()) {
            srv6_routing_Type = (byte)Node.asInt();
        } else {
            srv6_routing_Type = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectSrv6_Routing_Type(srv6_routing_Type);
    }
}

private class Srv6_Segments_LeftDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_SEGMENTS_LEFT),
                                      CriterionCodec.SRV6_SEGMENTS_LEFT + MISSING_MEMBER_MESSAGE);
      	
      	byte srv6_segments_left;
        if (Node.isInt()) {
            srv6_segments_left = (byte)Node.asInt();
        } else {
            srv6_segments_left = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectSrv6_Segments_Left(srv6_segments_left);
    }
}

private class Srv6_Last_EntyDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_LAST_ENTY),
                                      CriterionCodec.SRV6_LAST_ENTY + MISSING_MEMBER_MESSAGE);
      	
      	byte srv6_last_enty;
        if (Node.isInt()) {
            srv6_last_enty = (byte)Node.asInt();
        } else {
            srv6_last_enty = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectSrv6_Last_Enty(srv6_last_enty);
    }
}

private class Srv6_FlagsDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_FLAGS),
                                      CriterionCodec.SRV6_FLAGS + MISSING_MEMBER_MESSAGE);
      	
      	byte srv6_flags;
        if (Node.isInt()) {
            srv6_flags = (byte)Node.asInt();
        } else {
            srv6_flags = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectSrv6_Flags(srv6_flags);
    }
}

private class Srv6_TagDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_TAG),
                                      CriterionCodec.SRV6_TAG + MISSING_MEMBER_MESSAGE);
      	
      	short srv6_tag;
        if (Node.isInt()) {
            srv6_tag = (short)Node.asInt();
        } else {
            srv6_tag = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectSrv6_Tag(srv6_tag);
    }
}

private class Srv6_Segmentlist3Decoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      byte[] data = HexStringToByteArray(nullIsIllegal(json.get(CriterionCodec.SRV6_SEGMENTLIST3),
                    CriterionCodec.SRV6_SEGMENTLIST3 + MISSING_MEMBER_MESSAGE).asText());
      
      Srv6_Segmentlist3 dst = Srv6_Segmentlist3.valueOf(data);
      
      return Criteria.selectSrv6_Segmentlist3(dst);
    }
}

private class Srv6_Segmentlist2Decoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      byte[] data = HexStringToByteArray(nullIsIllegal(json.get(CriterionCodec.SRV6_SEGMENTLIST2),
                    CriterionCodec.SRV6_SEGMENTLIST2 + MISSING_MEMBER_MESSAGE).asText());
      
      Srv6_Segmentlist2 dst = Srv6_Segmentlist2.valueOf(data);
      
      return Criteria.selectSrv6_Segmentlist2(dst);
    }
}

private class Srv6_Segmentlist1Decoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      byte[] data = HexStringToByteArray(nullIsIllegal(json.get(CriterionCodec.SRV6_SEGMENTLIST1),
                    CriterionCodec.SRV6_SEGMENTLIST1 + MISSING_MEMBER_MESSAGE).asText());
      
      Srv6_Segmentlist1 dst = Srv6_Segmentlist1.valueOf(data);
      
      return Criteria.selectSrv6_Segmentlist1(dst);
    }
}

private class Ipv6_Ver_Tp_Flb_IDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_VER_TP_FLB_I),
                                      CriterionCodec.IPV6_VER_TP_FLB_I + MISSING_MEMBER_MESSAGE);
      	
      	int ipv6_ver_tp_flb_i;
        if (Node.isInt()) {
            ipv6_ver_tp_flb_i = Node.asInt();
        } else {
            ipv6_ver_tp_flb_i = Integer.decode(Node.textValue());
        }
      
        return Criteria.selectIpv6_Ver_Tp_Flb_I(ipv6_ver_tp_flb_i);
    }
}

private class Ipv6_Plen_IDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_PLEN_I),
                                      CriterionCodec.IPV6_PLEN_I + MISSING_MEMBER_MESSAGE);
      	
      	short ipv6_plen_i;
        if (Node.isInt()) {
            ipv6_plen_i = (short)Node.asInt();
        } else {
            ipv6_plen_i = Integer.decode(Node.textValue()).shortValue();
        }
      
        return Criteria.selectIpv6_Plen_I(ipv6_plen_i);
    }
}

private class Ipv6_I_TypeDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_I_TYPE),
                                      CriterionCodec.IPV6_I_TYPE + MISSING_MEMBER_MESSAGE);
      	
      	byte ipv6_i_type;
        if (Node.isInt()) {
            ipv6_i_type = (byte)Node.asInt();
        } else {
            ipv6_i_type = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectIpv6_I_Type(ipv6_i_type);
    }
}

private class Ipv6_Hlmt_IDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
        JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_HLMT_I),
                                      CriterionCodec.IPV6_HLMT_I + MISSING_MEMBER_MESSAGE);
      	
      	byte ipv6_hlmt_i;
        if (Node.isInt()) {
            ipv6_hlmt_i = (byte)Node.asInt();
        } else {
            ipv6_hlmt_i = Integer.decode(Node.textValue()).byteValue();
        }
      
        return Criteria.selectIpv6_Hlmt_I(ipv6_hlmt_i);
    }
}

private class Ipv6_Src_IDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      byte[] data = new byte[Ipv6_Src_I.LEN];
      byte[] mask = new byte[Ipv6_Src_I.LEN];
      
      parseIpAddress(nullIsIllegal(json.get(CriterionCodec.IPV6_SRC_I),
                    CriterionCodec.IPV6_SRC_I + MISSING_MEMBER_MESSAGE).asText(), data, mask);
      
      Ipv6_Src_I IPData = Ipv6_Src_I.valueOf(data);
      Ipv6_Src_I IPMask = Ipv6_Src_I.valueOf(mask);
      return Criteria.selectIpv6_Src_I(IPData, IPMask);
    }
}

private class Ipv6_Dst_IDecoder implements CriterionDecoder {
    @Override
    public Criterion decodeCriterion(ObjectNode json) {
      byte[] data = new byte[Ipv6_Dst_I.LEN];
      byte[] mask = new byte[Ipv6_Dst_I.LEN];
      
      parseIpAddress(nullIsIllegal(json.get(CriterionCodec.IPV6_DST_I),
                    CriterionCodec.IPV6_DST_I + MISSING_MEMBER_MESSAGE).asText(), data, mask);
      
      Ipv6_Dst_I IPData = Ipv6_Dst_I.valueOf(data);
      Ipv6_Dst_I IPMask = Ipv6_Dst_I.valueOf(mask);
      return Criteria.selectIpv6_Dst_I(IPData, IPMask);
    }
}


    public static byte[] macAddressToByteArray(String macAddress) {
        String[] hexParts = macAddress.split("[:-]");
        if (hexParts.length != 6) {
            throw new IllegalArgumentException("Invalid MAC address format.");
        }
        byte[] bytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            bytes[i] = (byte) Integer.parseInt(hexParts[i], 16);
        }
        return bytes;
    }

    public static void parseIpAddress(String ipAddressWithMask, byte[] ipAddressBytes, byte[] maskBytes) {
        String[] parts = ipAddressWithMask.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid IP address format with mask.");
        }

        String ipAddress = parts[0];
        int maskLength = Integer.parseInt(parts[1]);

        try {
            byte[] parsedIpAddressBytes = InetAddress.getByName(ipAddress).getAddress();
            if (parsedIpAddressBytes.length != ipAddressBytes.length) {
                throw new IllegalArgumentException("IP address length does not match provided byte array length.");
            }

            System.arraycopy(parsedIpAddressBytes, 0, ipAddressBytes, 0, parsedIpAddressBytes.length);

            int byteCount = maskLength / 8;
            int remainingBits = maskLength % 8;

            Arrays.fill(maskBytes, 0, byteCount, (byte) 0xFF);

            if (remainingBits > 0) {
                int finalByte = (0xFF << (8 - remainingBits)) & 0xFF;
                maskBytes[byteCount] = (byte) finalByte;
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid IP address format.", e);
        }
    }

    public static byte[] HexStringToByteArray(String hexString){
        byte[] byteArray = new BigInteger(hexString, 16).toByteArray();

        if (byteArray[0] == 0) {
            byte[] temp = new byte[byteArray.length - 1];
            System.arraycopy(byteArray, 1, temp, 0, temp.length);
            byteArray = temp;
        }
    
        return byteArray;
    }
    
}