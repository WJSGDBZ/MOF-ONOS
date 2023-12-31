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
import org.projectfloodlight.openflow.protocol.OFBsnUdfAnchor;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;

public class OFBsnUdfAnchorSerializerVer13 {

    public final static short BSN_UDF_ANCHOR_PACKET_START_VAL = (short) 0x0;
    public final static short BSN_UDF_ANCHOR_L3_HEADER_START_VAL = (short) 0x1;
    public final static short BSN_UDF_ANCHOR_L4_HEADER_START_VAL = (short) 0x2;
    public final static short BSN_UDF_ANCHOR_TD3_L2_START_VAL = (short) 0x3;
    public final static short BSN_UDF_ANCHOR_TD3_L3_IPV4_START_WITHOUT_OPTIONS_VAL = (short) 0x4;
    public final static short BSN_UDF_ANCHOR_TD3_L3_IPV6_START_VAL = (short) 0x5;
    public final static short BSN_UDF_ANCHOR_TD3_UDP_UNKNOWN_L5_START_VAL = (short) 0x6;

    public static OFBsnUdfAnchor readFrom(ByteBuf bb) throws OFParseError {
        try {
            return ofWireValue(bb.readShort());
        } catch (IllegalArgumentException e) {
            throw new OFParseError(e);
        }
    }

    public static void writeTo(ByteBuf bb, OFBsnUdfAnchor e) {
        bb.writeShort(toWireValue(e));
    }

    public static void putTo(OFBsnUdfAnchor e, PrimitiveSink sink) {
        sink.putShort(toWireValue(e));
    }

    public static OFBsnUdfAnchor ofWireValue(short val) {
        switch(val) {
            case BSN_UDF_ANCHOR_PACKET_START_VAL:
                return OFBsnUdfAnchor.BSN_UDF_ANCHOR_PACKET_START;
            case BSN_UDF_ANCHOR_L3_HEADER_START_VAL:
                return OFBsnUdfAnchor.BSN_UDF_ANCHOR_L3_HEADER_START;
            case BSN_UDF_ANCHOR_L4_HEADER_START_VAL:
                return OFBsnUdfAnchor.BSN_UDF_ANCHOR_L4_HEADER_START;
            case BSN_UDF_ANCHOR_TD3_L2_START_VAL:
                return OFBsnUdfAnchor.BSN_UDF_ANCHOR_TD3_L2_START;
            case BSN_UDF_ANCHOR_TD3_L3_IPV4_START_WITHOUT_OPTIONS_VAL:
                return OFBsnUdfAnchor.BSN_UDF_ANCHOR_TD3_L3_IPV4_START_WITHOUT_OPTIONS;
            case BSN_UDF_ANCHOR_TD3_L3_IPV6_START_VAL:
                return OFBsnUdfAnchor.BSN_UDF_ANCHOR_TD3_L3_IPV6_START;
            case BSN_UDF_ANCHOR_TD3_UDP_UNKNOWN_L5_START_VAL:
                return OFBsnUdfAnchor.BSN_UDF_ANCHOR_TD3_UDP_UNKNOWN_L5_START;
            default:
                throw new IllegalArgumentException("Illegal wire value for type OFBsnUdfAnchor in version 1.3: " + val);
        }
    }


    public static short toWireValue(OFBsnUdfAnchor e) {
        switch(e) {
            case BSN_UDF_ANCHOR_PACKET_START:
                return BSN_UDF_ANCHOR_PACKET_START_VAL;
            case BSN_UDF_ANCHOR_L3_HEADER_START:
                return BSN_UDF_ANCHOR_L3_HEADER_START_VAL;
            case BSN_UDF_ANCHOR_L4_HEADER_START:
                return BSN_UDF_ANCHOR_L4_HEADER_START_VAL;
            case BSN_UDF_ANCHOR_TD3_L2_START:
                return BSN_UDF_ANCHOR_TD3_L2_START_VAL;
            case BSN_UDF_ANCHOR_TD3_L3_IPV4_START_WITHOUT_OPTIONS:
                return BSN_UDF_ANCHOR_TD3_L3_IPV4_START_WITHOUT_OPTIONS_VAL;
            case BSN_UDF_ANCHOR_TD3_L3_IPV6_START:
                return BSN_UDF_ANCHOR_TD3_L3_IPV6_START_VAL;
            case BSN_UDF_ANCHOR_TD3_UDP_UNKNOWN_L5_START:
                return BSN_UDF_ANCHOR_TD3_UDP_UNKNOWN_L5_START_VAL;
            default:
                throw new IllegalArgumentException("Illegal enum value for type OFBsnUdfAnchor in version 1.3: " + e);
        }
    }

}
