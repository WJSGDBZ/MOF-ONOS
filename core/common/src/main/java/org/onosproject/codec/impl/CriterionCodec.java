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

import org.onosproject.codec.CodecContext;
import org.onosproject.codec.JsonCodec;
import org.onosproject.net.flow.criteria.Criterion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Criterion codec.
 */
public final class CriterionCodec extends JsonCodec<Criterion> {

    private static final Logger log =
            LoggerFactory.getLogger(CriterionCodec.class);

    static final String TYPE = "type";
    static final String ETH_TYPE = "ethType";
    static final String MAC = "mac";
    static final String MAC_MASK = "macMask";
    static final String PORT = "port";
    static final String METADATA = "metadata";

    static final String VLAN_ID = "vlanId";
    static final String INNER_VLAN_ID = "innerVlanId";
    static final String INNER_PRIORITY = "innerPriority";
    static final String PRIORITY = "priority";
    static final String IP_DSCP = "ipDscp";
    static final String IP_ECN = "ipEcn";
    static final String PROTOCOL = "protocol";
    static final String IP = "ip";
    static final String TCP_PORT = "tcpPort";
    static final String TCP_MASK = "tcpMask";
    static final String UDP_PORT = "udpPort";
    static final String UDP_MASK = "udpMask";
    static final String SCTP_PORT = "sctpPort";
    static final String SCTP_MASK = "sctpMask";
    static final String ICMP_TYPE = "icmpType";
    static final String ICMP_CODE = "icmpCode";
    static final String FLOW_LABEL = "flowLabel";
    static final String ICMPV6_TYPE = "icmpv6Type";
    static final String ICMPV6_CODE = "icmpv6Code";
    static final String TARGET_ADDRESS = "targetAddress";
    static final String LABEL = "label";
    static final String BOS = "bos";
    static final String EXT_HDR_FLAGS = "exthdrFlags";
    static final String LAMBDA = "lambda";
    static final String GRID_TYPE = "gridType";
    static final String CHANNEL_SPACING = "channelSpacing";
    static final String SPACING_MULIPLIER = "spacingMultiplier";
    static final String SLOT_GRANULARITY = "slotGranularity";
    static final String OCH_SIGNAL_ID = "ochSignalId";
    static final String TUNNEL_ID = "tunnelId";
    static final String OCH_SIGNAL_TYPE = "ochSignalType";
    static final String ODU_SIGNAL_ID = "oduSignalId";
    static final String TRIBUTARY_PORT_NUMBER = "tributaryPortNumber";
    static final String TRIBUTARY_SLOT_LEN = "tributarySlotLen";
    static final String TRIBUTARY_SLOT_BITMAP = "tributarySlotBitmap";
    static final String ODU_SIGNAL_TYPE = "oduSignalType";
    static final String PI_MATCHES = "matches";
    static final String PI_MATCH_FIELD_ID = "field";
    static final String PI_MATCH_TYPE = "match";
    static final String PI_MATCH_VALUE = "value";
    static final String PI_MATCH_PREFIX = "prefixLength";
    static final String PI_MATCH_MASK = "mask";
    static final String PI_MATCH_HIGH_VALUE = "highValue";
    static final String PI_MATCH_LOW_VALUE = "lowValue";
    static final String EXTENSION = "extension";

    static final String MAC_DST = "mac_dst";
    static final String MAC_SRC = "mac_src";
    static final String VLAN1_TPID = "vlan1_tpid";
    static final String VLAN1_QID = "vlan1_qid";
    static final String VLAN2_TPID = "vlan2_tpid";
    static final String VLAN2_QID = "vlan2_qid";
    static final String DL_TYPE = "dl_type";
    static final String VER_HL_E = "ver_hl_e";
    static final String TOS_E = "tos_e";
    static final String TOT_LEN_E = "tot_len_e";
    static final String IP_ID_E = "ip_id_e";
    static final String FRAG_OFF_E = "frag_off_e";
    static final String TTL_E = "ttl_e";
    static final String IPV4_E_TYPE = "ipv4_e_type";
    static final String IP_CHECK_E = "ip_check_e";
    static final String IP_SADDR_E = "ip_saddr_e";
    static final String IP_DADDR_E = "ip_daddr_e";
    static final String IPV6_VER_TP_FLB_E = "ipv6_ver_tp_flb_e";
    static final String IPV6_PLEN_E = "ipv6_plen_e";
    static final String IPV6_E_TYPE = "ipv6_e_type";
    static final String IPV6_HLMT_E = "ipv6_hlmt_e";
    static final String IPV6_SRC_E = "ipv6_src_e";
    static final String IPV6_DST_E = "ipv6_dst_e";
    static final String TCP_SOURCE = "tcp_source";
    static final String TCP_DEST = "tcp_dest";
    static final String SEQ = "seq";
    static final String ACK_SEQ = "ack_seq";
    static final String OFF_BITS = "off_bits";
    static final String WINDOW = "window";
    static final String TCP_CHECK = "tcp_check";
    static final String URG_PTR = "urg_ptr";
    static final String UDP_SOURCE = "udp_source";
    static final String UDP_DEST = "udp_dest";
    static final String LEN = "len";
    static final String UDP_CHECK = "udp_check";
    static final String SRV6_TYPE = "srv6_type";
    static final String SRV6_HDR_EXT_LEN = "srv6_hdr_ext_len";
    static final String SRV6_ROUTING_TYPE = "srv6_routing_Type";
    static final String SRV6_SEGMENTS_LEFT = "srv6_segments_left";
    static final String SRV6_LAST_ENTY = "srv6_last_enty";
    static final String SRV6_FLAGS = "srv6_flags";
    static final String SRV6_TAG = "srv6_tag";
    static final String SRV6_SEGMENTLIST3 = "srv6_segmentlist3";
    static final String SRV6_SEGMENTLIST2 = "srv6_segmentlist2";
    static final String SRV6_SEGMENTLIST1 = "srv6_segmentlist1";
    static final String IPV6_VER_TP_FLB_I = "ipv6_ver_tp_flb_i";
    static final String IPV6_PLEN_I = "ipv6_plen_i";
    static final String IPV6_I_TYPE = "ipv6_i_type";
    static final String IPV6_HLMT_I = "ipv6_hlmt_i";
    static final String IPV6_SRC_I = "ipv6_src_i";
    static final String IPV6_DST_I = "ipv6_dst_i";
    static final String VER_HL_I = "ver_hl_i";
    static final String TOS_I = "tos_i";
    static final String TOT_LEN_I = "tot_len_i";
    static final String IP_ID_I = "ip_id_i";
    static final String FRAG_OFF_I = "frag_off_i";
    static final String TTL_I = "ttl_i";
    static final String IPV4_I_TYPE = "ipv4_i_type";
    static final String IP_CHECK_I = "ip_check_i";
    static final String IP_SADDR_I = "ip_saddr_i";
    static final String IP_DADDR_I = "ip_daddr_i";

    @Override
    public ObjectNode encode(Criterion criterion, CodecContext context) {
        EncodeCriterionCodecHelper encoder = new EncodeCriterionCodecHelper(criterion, context);
        return encoder.encode();
    }

    @Override
    public Criterion decode(ObjectNode json, CodecContext context) {
        DecodeCriterionCodecHelper decoder = new DecodeCriterionCodecHelper(json);
        return decoder.decode();
    }
}