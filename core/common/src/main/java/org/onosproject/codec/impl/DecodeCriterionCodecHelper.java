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
import org.onosproject.net.flow.criteria.Srv6_Segmentlist2Criterion;
import org.onosproject.net.flow.criteria.Srv6_Segmentlist3Criterion;
import org.onosproject.net.flow.criteria.Ipv6_Ver_Tp_Flb_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Plen_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_I_TypeCriterion;
import org.onosproject.net.flow.criteria.Ipv6_Hlmt_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Src_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Dst_ICriterion;
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
    decoderMap.put(Criterion.Type.TCP_SOURCE.name(), new Tcp_SourceDecoder());
    decoderMap.put(Criterion.Type.TCP_DEST.name(), new Tcp_DestDecoder());
    decoderMap.put(Criterion.Type.SEQ.name(), new SeqDecoder());
    decoderMap.put(Criterion.Type.ACK_SEQ.name(), new Ack_SeqDecoder());
    decoderMap.put(Criterion.Type.OFF_BITS.name(), new Off_BitsDecoder());
    decoderMap.put(Criterion.Type.WINDOW.name(), new WindowDecoder());
    decoderMap.put(Criterion.Type.TCP_CHECK.name(), new Tcp_CheckDecoder());
    decoderMap.put(Criterion.Type.URG_PTR.name(), new Urg_PtrDecoder());
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
    decoderMap.put(Criterion.Type.VER_HL_I.name(), new Ver_Hl_IDecoder());
    decoderMap.put(Criterion.Type.TOS_I.name(), new Tos_IDecoder());
    decoderMap.put(Criterion.Type.TOT_LEN_I.name(), new Tot_Len_IDecoder());
    decoderMap.put(Criterion.Type.IP_ID_I.name(), new Ip_Id_IDecoder());
    decoderMap.put(Criterion.Type.FRAG_OFF_I.name(), new Frag_Off_IDecoder());
    decoderMap.put(Criterion.Type.TTL_I.name(), new Ttl_IDecoder());
    decoderMap.put(Criterion.Type.IPV4_I_TYPE.name(), new Ipv4_I_TypeDecoder());
    decoderMap.put(Criterion.Type.IP_CHECK_I.name(), new Ip_Check_IDecoder());
    decoderMap.put(Criterion.Type.IP_SADDR_I.name(), new Ip_Saddr_IDecoder());
    decoderMap.put(Criterion.Type.IP_DADDR_I.name(), new Ip_Daddr_IDecoder());
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
            String str = nullIsIllegal(json.get(CriterionCodec.MAC_DST), CriterionCodec.MAC_DST + 
                                        MISSING_MEMBER_MESSAGE).asText();
            if(str.contains("/")){
                String[] parts = str.split("/");
                byte[] data = HexStringToByteArray(parts[0]);
                byte[] mask = HexStringToByteArray(parts[1]);
                
                return Criteria.selectMac_Dst(Mac_Dst.valueOf(data), Mac_Dst.valueOf(mask));
            }else{
                byte[] data = HexStringToByteArray(str);

                return Criteria.selectMac_Dst(Mac_Dst.valueOf(data));
            }
        }
    }

    private class Mac_SrcDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String str = nullIsIllegal(json.get(CriterionCodec.MAC_SRC), CriterionCodec.MAC_SRC + 
                                        MISSING_MEMBER_MESSAGE).asText();
            if(str.contains("/")){
                String[] parts = str.split("/");
                byte[] data = HexStringToByteArray(parts[0]);
                byte[] mask = HexStringToByteArray(parts[1]);
                
                return Criteria.selectMac_Src(Mac_Src.valueOf(data), Mac_Src.valueOf(mask));
            }else{
                byte[] data = HexStringToByteArray(str);

                return Criteria.selectMac_Src(Mac_Src.valueOf(data));
            }
        }
    }

    private class Vlan1_TpidDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VLAN1_TPID),
                                        CriterionCodec.VLAN1_TPID + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectVlan1_Tpid(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectVlan1_Tpid(data);
            }
        }
    }

    private class Vlan1_QidDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VLAN1_QID),
                                        CriterionCodec.VLAN1_QID + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectVlan1_Qid(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectVlan1_Qid(data);
            }
        }
    }

    private class Vlan2_TpidDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VLAN2_TPID),
                                        CriterionCodec.VLAN2_TPID + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectVlan2_Tpid(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectVlan2_Tpid(data);
            }
        }
    }

    private class Vlan2_QidDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VLAN2_QID),
                                        CriterionCodec.VLAN2_QID + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectVlan2_Qid(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectVlan2_Qid(data);
            }
        }
    }

    private class Dl_TypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.DL_TYPE),
                                        CriterionCodec.DL_TYPE + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectDl_Type(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectDl_Type(data);
            }
        }
    }

    private class Ver_Hl_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VER_HL_E),
                                        CriterionCodec.VER_HL_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectVer_Hl_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectVer_Hl_E(data);
            }
        }
    }

    private class Tos_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TOS_E),
                                        CriterionCodec.TOS_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectTos_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectTos_E(data);
            }
        }
    }

    private class Tot_Len_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TOT_LEN_E),
                                        CriterionCodec.TOT_LEN_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectTot_Len_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectTot_Len_E(data);
            }
        }
    }

    private class Ip_Id_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_ID_E),
                                        CriterionCodec.IP_ID_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIp_Id_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIp_Id_E(data);
            }
        }
    }

    private class Frag_Off_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.FRAG_OFF_E),
                                        CriterionCodec.FRAG_OFF_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectFrag_Off_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectFrag_Off_E(data);
            }
        }
    }

    private class Ttl_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TTL_E),
                                        CriterionCodec.TTL_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectTtl_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectTtl_E(data);
            }
        }
    }

    private class Ipv4_E_TypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV4_E_TYPE),
                                        CriterionCodec.IPV4_E_TYPE + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv4_E_Type(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv4_E_Type(data);
            }
        }
    }

    private class Ip_Check_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_CHECK_E),
                                        CriterionCodec.IP_CHECK_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIp_Check_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIp_Check_E(data);
            }
        }
    }

    private class Ip_Saddr_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_SADDR_E),
                                        CriterionCodec.IP_SADDR_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIp_Saddr_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIp_Saddr_E(data);
            }
        }
    }

    private class Ip_Daddr_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_DADDR_E),
                                        CriterionCodec.IP_DADDR_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIp_Daddr_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIp_Daddr_E(data);
            }
        }
    }

    private class Ipv6_Ver_Tp_Flb_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_VER_TP_FLB_E),
                                        CriterionCodec.IPV6_VER_TP_FLB_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv6_Ver_Tp_Flb_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv6_Ver_Tp_Flb_E(data);
            }
        }
    }

    private class Ipv6_Plen_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_PLEN_E),
                                        CriterionCodec.IPV6_PLEN_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv6_Plen_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv6_Plen_E(data);
            }
        }
    }

    private class Ipv6_E_TypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_E_TYPE),
                                        CriterionCodec.IPV6_E_TYPE + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv6_E_Type(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv6_E_Type(data);
            }
        }
    }

    private class Ipv6_Hlmt_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_HLMT_E),
                                        CriterionCodec.IPV6_HLMT_E + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv6_Hlmt_E(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv6_Hlmt_E(data);
            }
        }
    }

    private class Ipv6_Src_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String str = nullIsIllegal(json.get(CriterionCodec.IPV6_SRC_E), CriterionCodec.IPV6_SRC_E + 
                                        MISSING_MEMBER_MESSAGE).asText();
            if(str.contains("/")){
                String[] parts = str.split("/");
                byte[] data = HexStringToByteArray(parts[0]);
                byte[] mask = HexStringToByteArray(parts[1]);
                
                return Criteria.selectIpv6_Src_E(Ipv6_Src_E.valueOf(data), Ipv6_Src_E.valueOf(mask));
            }else{
                byte[] data = HexStringToByteArray(str);

                return Criteria.selectIpv6_Src_E(Ipv6_Src_E.valueOf(data));
            }
        }
    }

    private class Ipv6_Dst_EDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String str = nullIsIllegal(json.get(CriterionCodec.IPV6_DST_E), CriterionCodec.IPV6_DST_E + 
                                        MISSING_MEMBER_MESSAGE).asText();
            if(str.contains("/")){
                String[] parts = str.split("/");
                byte[] data = HexStringToByteArray(parts[0]);
                byte[] mask = HexStringToByteArray(parts[1]);
                
                return Criteria.selectIpv6_Dst_E(Ipv6_Dst_E.valueOf(data), Ipv6_Dst_E.valueOf(mask));
            }else{
                byte[] data = HexStringToByteArray(str);

                return Criteria.selectIpv6_Dst_E(Ipv6_Dst_E.valueOf(data));
            }
        }
    }

    private class Tcp_SourceDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TCP_SOURCE),
                                        CriterionCodec.TCP_SOURCE + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectTcp_Source(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectTcp_Source(data);
            }
        }
    }

    private class Tcp_DestDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TCP_DEST),
                                        CriterionCodec.TCP_DEST + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectTcp_Dest(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectTcp_Dest(data);
            }
        }
    }

    private class SeqDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SEQ),
                                        CriterionCodec.SEQ + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectSeq(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectSeq(data);
            }
        }
    }

    private class Ack_SeqDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.ACK_SEQ),
                                        CriterionCodec.ACK_SEQ + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectAck_Seq(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectAck_Seq(data);
            }
        }
    }

    private class Off_BitsDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.OFF_BITS),
                                        CriterionCodec.OFF_BITS + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectOff_Bits(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectOff_Bits(data);
            }
        }
    }

    private class WindowDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.WINDOW),
                                        CriterionCodec.WINDOW + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectWindow(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectWindow(data);
            }
        }
    }

    private class Tcp_CheckDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TCP_CHECK),
                                        CriterionCodec.TCP_CHECK + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectTcp_Check(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectTcp_Check(data);
            }
        }
    }

    private class Urg_PtrDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.URG_PTR),
                                        CriterionCodec.URG_PTR + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectUrg_Ptr(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectUrg_Ptr(data);
            }
        }
    }

    private class Udp_SourceDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.UDP_SOURCE),
                                        CriterionCodec.UDP_SOURCE + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectUdp_Source(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectUdp_Source(data);
            }
        }
    }

    private class Udp_DestDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.UDP_DEST),
                                        CriterionCodec.UDP_DEST + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectUdp_Dest(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectUdp_Dest(data);
            }
        }
    }

    private class LenDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.LEN),
                                        CriterionCodec.LEN + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectLen(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectLen(data);
            }
        }
    }

    private class Udp_CheckDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.UDP_CHECK),
                                        CriterionCodec.UDP_CHECK + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectUdp_Check(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectUdp_Check(data);
            }
        }
    }

    private class Srv6_TypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_TYPE),
                                        CriterionCodec.SRV6_TYPE + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectSrv6_Type(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectSrv6_Type(data);
            }
        }
    }

    private class Srv6_Hdr_Ext_LenDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_HDR_EXT_LEN),
                                        CriterionCodec.SRV6_HDR_EXT_LEN + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectSrv6_Hdr_Ext_Len(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectSrv6_Hdr_Ext_Len(data);
            }
        }
    }

    private class Srv6_Routing_TypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_ROUTING_TYPE),
                                        CriterionCodec.SRV6_ROUTING_TYPE + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectSrv6_Routing_Type(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectSrv6_Routing_Type(data);
            }
        }
    }

    private class Srv6_Segments_LeftDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_SEGMENTS_LEFT),
                                        CriterionCodec.SRV6_SEGMENTS_LEFT + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectSrv6_Segments_Left(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectSrv6_Segments_Left(data);
            }
        }
    }

    private class Srv6_Last_EntyDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_LAST_ENTY),
                                        CriterionCodec.SRV6_LAST_ENTY + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectSrv6_Last_Enty(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectSrv6_Last_Enty(data);
            }
        }
    }

    private class Srv6_FlagsDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_FLAGS),
                                        CriterionCodec.SRV6_FLAGS + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectSrv6_Flags(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectSrv6_Flags(data);
            }
        }
    }

    private class Srv6_TagDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.SRV6_TAG),
                                        CriterionCodec.SRV6_TAG + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectSrv6_Tag(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectSrv6_Tag(data);
            }
        }
    }

    private class Srv6_Segmentlist3Decoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String str = nullIsIllegal(json.get(CriterionCodec.SRV6_SEGMENTLIST3), CriterionCodec.SRV6_SEGMENTLIST3 + 
                                        MISSING_MEMBER_MESSAGE).asText();
            if(str.contains("/")){
                String[] parts = str.split("/");
                byte[] data = HexStringToByteArray(parts[0]);
                byte[] mask = HexStringToByteArray(parts[1]);
                
                return Criteria.selectSrv6_Segmentlist3(Srv6_Segmentlist3.valueOf(data), Srv6_Segmentlist3.valueOf(mask));
            }else{
                byte[] data = HexStringToByteArray(str);

                return Criteria.selectSrv6_Segmentlist3(Srv6_Segmentlist3.valueOf(data));
            }
        }
    }

    private class Srv6_Segmentlist2Decoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String str = nullIsIllegal(json.get(CriterionCodec.SRV6_SEGMENTLIST2), CriterionCodec.SRV6_SEGMENTLIST2 + 
                                        MISSING_MEMBER_MESSAGE).asText();
            if(str.contains("/")){
                String[] parts = str.split("/");
                byte[] data = HexStringToByteArray(parts[0]);
                byte[] mask = HexStringToByteArray(parts[1]);
                
                return Criteria.selectSrv6_Segmentlist2(Srv6_Segmentlist2.valueOf(data), Srv6_Segmentlist2.valueOf(mask));
            }else{
                byte[] data = HexStringToByteArray(str);

                return Criteria.selectSrv6_Segmentlist2(Srv6_Segmentlist2.valueOf(data));
            }
        }
    }

    private class Srv6_Segmentlist1Decoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String str = nullIsIllegal(json.get(CriterionCodec.SRV6_SEGMENTLIST1), CriterionCodec.SRV6_SEGMENTLIST1 + 
                                        MISSING_MEMBER_MESSAGE).asText();
            if(str.contains("/")){
                String[] parts = str.split("/");
                byte[] data = HexStringToByteArray(parts[0]);
                byte[] mask = HexStringToByteArray(parts[1]);
                
                return Criteria.selectSrv6_Segmentlist1(Srv6_Segmentlist1.valueOf(data), Srv6_Segmentlist1.valueOf(mask));
            }else{
                byte[] data = HexStringToByteArray(str);

                return Criteria.selectSrv6_Segmentlist1(Srv6_Segmentlist1.valueOf(data));
            }
        }
    }

    private class Ipv6_Ver_Tp_Flb_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_VER_TP_FLB_I),
                                        CriterionCodec.IPV6_VER_TP_FLB_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv6_Ver_Tp_Flb_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv6_Ver_Tp_Flb_I(data);
            }
        }
    }

    private class Ipv6_Plen_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_PLEN_I),
                                        CriterionCodec.IPV6_PLEN_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv6_Plen_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv6_Plen_I(data);
            }
        }
    }

    private class Ipv6_I_TypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_I_TYPE),
                                        CriterionCodec.IPV6_I_TYPE + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv6_I_Type(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv6_I_Type(data);
            }
        }
    }

    private class Ipv6_Hlmt_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV6_HLMT_I),
                                        CriterionCodec.IPV6_HLMT_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv6_Hlmt_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv6_Hlmt_I(data);
            }
        }
    }

    private class Ipv6_Src_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String str = nullIsIllegal(json.get(CriterionCodec.IPV6_SRC_I), CriterionCodec.IPV6_SRC_I + 
                                        MISSING_MEMBER_MESSAGE).asText();
            if(str.contains("/")){
                String[] parts = str.split("/");
                byte[] data = HexStringToByteArray(parts[0]);
                byte[] mask = HexStringToByteArray(parts[1]);
                
                return Criteria.selectIpv6_Src_I(Ipv6_Src_I.valueOf(data), Ipv6_Src_I.valueOf(mask));
            }else{
                byte[] data = HexStringToByteArray(str);

                return Criteria.selectIpv6_Src_I(Ipv6_Src_I.valueOf(data));
            }
        }
    }

    private class Ipv6_Dst_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            String str = nullIsIllegal(json.get(CriterionCodec.IPV6_DST_I), CriterionCodec.IPV6_DST_I + 
                                        MISSING_MEMBER_MESSAGE).asText();
            if(str.contains("/")){
                String[] parts = str.split("/");
                byte[] data = HexStringToByteArray(parts[0]);
                byte[] mask = HexStringToByteArray(parts[1]);
                
                return Criteria.selectIpv6_Dst_I(Ipv6_Dst_I.valueOf(data), Ipv6_Dst_I.valueOf(mask));
            }else{
                byte[] data = HexStringToByteArray(str);

                return Criteria.selectIpv6_Dst_I(Ipv6_Dst_I.valueOf(data));
            }
        }
    }

    private class Ver_Hl_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.VER_HL_I),
                                        CriterionCodec.VER_HL_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectVer_Hl_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectVer_Hl_I(data);
            }
        }
    }

    private class Tos_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TOS_I),
                                        CriterionCodec.TOS_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectTos_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectTos_I(data);
            }
        }
    }

    private class Tot_Len_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TOT_LEN_I),
                                        CriterionCodec.TOT_LEN_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectTot_Len_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectTot_Len_I(data);
            }
        }
    }

    private class Ip_Id_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_ID_I),
                                        CriterionCodec.IP_ID_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIp_Id_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIp_Id_I(data);
            }
        }
    }

    private class Frag_Off_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.FRAG_OFF_I),
                                        CriterionCodec.FRAG_OFF_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectFrag_Off_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectFrag_Off_I(data);
            }
        }
    }

    private class Ttl_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.TTL_I),
                                        CriterionCodec.TTL_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectTtl_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectTtl_I(data);
            }
        }
    }

    private class Ipv4_I_TypeDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IPV4_I_TYPE),
                                        CriterionCodec.IPV4_I_TYPE + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIpv4_I_Type(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIpv4_I_Type(data);
            }
        }
    }

    private class Ip_Check_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_CHECK_I),
                                        CriterionCodec.IP_CHECK_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIp_Check_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIp_Check_I(data);
            }
        }
    }

    private class Ip_Saddr_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_SADDR_I),
                                        CriterionCodec.IP_SADDR_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIp_Saddr_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIp_Saddr_I(data);
            }
        }
    }

    private class Ip_Daddr_IDecoder implements CriterionDecoder {
        @Override
        public Criterion decodeCriterion(ObjectNode json) {
            JsonNode Node = nullIsIllegal(json.get(CriterionCodec.IP_DADDR_I),
                                        CriterionCodec.IP_DADDR_I + MISSING_MEMBER_MESSAGE);
            
            String str = Node.textValue();
            if(str.contains("/")){
                String[] parts = str.split("/");

                if (parts[0].startsWith("0x")) {
                    parts[0] = parts[0].substring(2);
                }
                long data = Long.parseLong(parts[0], 16);
                
                if (parts[1].startsWith("0x")) {
                    parts[1] = parts[1].substring(2);
                }
                long mask = Long.parseLong(parts[1], 16);

                return Criteria.selectIp_Daddr_I(data, mask);
            }else{
                if (str.startsWith("0x")) {
                    str = str.substring(2);
                }
                long data =  Long.parseLong(str, 16);
                return Criteria.selectIp_Daddr_I(data);
            }
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