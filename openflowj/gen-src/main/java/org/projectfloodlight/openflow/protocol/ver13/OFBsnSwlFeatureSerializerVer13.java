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
import org.projectfloodlight.openflow.protocol.OFBsnSwlFeature;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;

public class OFBsnSwlFeatureSerializerVer13 {

    public final static short BSN_SWL_FEATURE_ALLOW_PEER_TO_EDGE_UNICAST_VAL = (short) 0x0;
    public final static short BSN_SWL_FEATURE_DROP_DUPLICATE_L3CPU_VAL = (short) 0x1;
    public final static short BSN_SWL_FEATURE_COUNT_VAL = (short) 0x2;

    public static OFBsnSwlFeature readFrom(ByteBuf bb) throws OFParseError {
        try {
            return ofWireValue(bb.readShort());
        } catch (IllegalArgumentException e) {
            throw new OFParseError(e);
        }
    }

    public static void writeTo(ByteBuf bb, OFBsnSwlFeature e) {
        bb.writeShort(toWireValue(e));
    }

    public static void putTo(OFBsnSwlFeature e, PrimitiveSink sink) {
        sink.putShort(toWireValue(e));
    }

    public static OFBsnSwlFeature ofWireValue(short val) {
        switch(val) {
            case BSN_SWL_FEATURE_ALLOW_PEER_TO_EDGE_UNICAST_VAL:
                return OFBsnSwlFeature.BSN_SWL_FEATURE_ALLOW_PEER_TO_EDGE_UNICAST;
            case BSN_SWL_FEATURE_DROP_DUPLICATE_L3CPU_VAL:
                return OFBsnSwlFeature.BSN_SWL_FEATURE_DROP_DUPLICATE_L3CPU;
            case BSN_SWL_FEATURE_COUNT_VAL:
                return OFBsnSwlFeature.BSN_SWL_FEATURE_COUNT;
            default:
                throw new IllegalArgumentException("Illegal wire value for type OFBsnSwlFeature in version 1.3: " + val);
        }
    }


    public static short toWireValue(OFBsnSwlFeature e) {
        switch(e) {
            case BSN_SWL_FEATURE_ALLOW_PEER_TO_EDGE_UNICAST:
                return BSN_SWL_FEATURE_ALLOW_PEER_TO_EDGE_UNICAST_VAL;
            case BSN_SWL_FEATURE_DROP_DUPLICATE_L3CPU:
                return BSN_SWL_FEATURE_DROP_DUPLICATE_L3CPU_VAL;
            case BSN_SWL_FEATURE_COUNT:
                return BSN_SWL_FEATURE_COUNT_VAL;
            default:
                throw new IllegalArgumentException("Illegal enum value for type OFBsnSwlFeature in version 1.3: " + e);
        }
    }

}
