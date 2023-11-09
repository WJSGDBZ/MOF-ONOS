// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template const_serializer.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver13;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.*;
import org.projectfloodlight.openflow.protocol.actionid.*;
import org.projectfloodlight.openflow.protocol.bsntlv.*;
import org.projectfloodlight.openflow.protocol.errormsg.*;
import org.projectfloodlight.openflow.protocol.meterband.*;
import org.projectfloodlight.openflow.protocol.instruction.*;
import org.projectfloodlight.openflow.protocol.instructionid.*;
import org.projectfloodlight.openflow.protocol.match.*;
import org.projectfloodlight.openflow.protocol.stat.*;
import org.projectfloodlight.openflow.protocol.oxm.*;
import org.projectfloodlight.openflow.protocol.oxs.*;
import org.projectfloodlight.openflow.protocol.queueprop.*;
import org.projectfloodlight.openflow.types.*;
import org.projectfloodlight.openflow.util.*;
import org.projectfloodlight.openflow.exceptions.*;
import org.projectfloodlight.openflow.protocol.OFBsnRoutingParam;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;

public class OFBsnRoutingParamSerializerVer13 {

    public final static short BSN_ROUTING_PARAM_OSPF_UCAST_VAL = (short) 0x1;
    public final static short BSN_ROUTING_PARAM_OSPF_MCAST_VAL = (short) 0x2;
    public final static short BSN_ROUTING_PARAM_ARP_FRR_VAL = (short) 0x3;
    public final static short BSN_ROUTING_PARAM_IPV6_OSPF_UCAST_VAL = (short) 0x4;
    public final static short BSN_ROUTING_PARAM_IPV6_OSPF_MCAST_VAL = (short) 0x5;
    public final static short BSN_ROUTING_PARAM_IPV6_NDP_FRR_VAL = (short) 0x6;

    public static OFBsnRoutingParam readFrom(ByteBuf bb) throws OFParseError {
        try {
            return ofWireValue(bb.readShort());
        } catch (IllegalArgumentException e) {
            throw new OFParseError(e);
        }
    }

    public static void writeTo(ByteBuf bb, OFBsnRoutingParam e) {
        bb.writeShort(toWireValue(e));
    }

    public static void putTo(OFBsnRoutingParam e, PrimitiveSink sink) {
        sink.putShort(toWireValue(e));
    }

    public static OFBsnRoutingParam ofWireValue(short val) {
        switch(val) {
            case BSN_ROUTING_PARAM_OSPF_UCAST_VAL:
                return OFBsnRoutingParam.BSN_ROUTING_PARAM_OSPF_UCAST;
            case BSN_ROUTING_PARAM_OSPF_MCAST_VAL:
                return OFBsnRoutingParam.BSN_ROUTING_PARAM_OSPF_MCAST;
            case BSN_ROUTING_PARAM_ARP_FRR_VAL:
                return OFBsnRoutingParam.BSN_ROUTING_PARAM_ARP_FRR;
            case BSN_ROUTING_PARAM_IPV6_OSPF_UCAST_VAL:
                return OFBsnRoutingParam.BSN_ROUTING_PARAM_IPV6_OSPF_UCAST;
            case BSN_ROUTING_PARAM_IPV6_OSPF_MCAST_VAL:
                return OFBsnRoutingParam.BSN_ROUTING_PARAM_IPV6_OSPF_MCAST;
            case BSN_ROUTING_PARAM_IPV6_NDP_FRR_VAL:
                return OFBsnRoutingParam.BSN_ROUTING_PARAM_IPV6_NDP_FRR;
            default:
                throw new IllegalArgumentException("Illegal wire value for type OFBsnRoutingParam in version 1.3: " + val);
        }
    }


    public static short toWireValue(OFBsnRoutingParam e) {
        switch(e) {
            case BSN_ROUTING_PARAM_OSPF_UCAST:
                return BSN_ROUTING_PARAM_OSPF_UCAST_VAL;
            case BSN_ROUTING_PARAM_OSPF_MCAST:
                return BSN_ROUTING_PARAM_OSPF_MCAST_VAL;
            case BSN_ROUTING_PARAM_ARP_FRR:
                return BSN_ROUTING_PARAM_ARP_FRR_VAL;
            case BSN_ROUTING_PARAM_IPV6_OSPF_UCAST:
                return BSN_ROUTING_PARAM_IPV6_OSPF_UCAST_VAL;
            case BSN_ROUTING_PARAM_IPV6_OSPF_MCAST:
                return BSN_ROUTING_PARAM_IPV6_OSPF_MCAST_VAL;
            case BSN_ROUTING_PARAM_IPV6_NDP_FRR:
                return BSN_ROUTING_PARAM_IPV6_NDP_FRR_VAL;
            default:
                throw new IllegalArgumentException("Illegal enum value for type OFBsnRoutingParam in version 1.3: " + e);
        }
    }

}
