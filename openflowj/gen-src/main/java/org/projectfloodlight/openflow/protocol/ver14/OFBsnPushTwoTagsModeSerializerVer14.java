// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template const_set_serializer.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver14;

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
import org.projectfloodlight.openflow.protocol.OFBsnPushTwoTagsMode;
import java.util.Set;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import java.util.EnumSet;
import java.util.Collections;


public class OFBsnPushTwoTagsModeSerializerVer14 {

    public final static byte BSN_PUSH_TWO_TAGS_NOT_SUPPORTED_VAL = (byte) 0x0;
    public final static byte BSN_PUSH_TWO_TAGS_SUPPORTED_VAL = (byte) 0x1;

    public static Set<OFBsnPushTwoTagsMode> readFrom(ByteBuf bb) throws OFParseError {
        try {
            return ofWireValue(bb.readByte());
        } catch (IllegalArgumentException e) {
            throw new OFParseError(e);
        }
    }

    public static void writeTo(ByteBuf bb, Set<OFBsnPushTwoTagsMode> set) {
        bb.writeByte(toWireValue(set));
    }

    public static void putTo(Set<OFBsnPushTwoTagsMode> set, PrimitiveSink sink) {
        sink.putByte(toWireValue(set));
    }


    public static Set<OFBsnPushTwoTagsMode> ofWireValue(byte val) {
        EnumSet<OFBsnPushTwoTagsMode> set = EnumSet.noneOf(OFBsnPushTwoTagsMode.class);

        if((val & BSN_PUSH_TWO_TAGS_NOT_SUPPORTED_VAL) != 0)
            set.add(OFBsnPushTwoTagsMode.BSN_PUSH_TWO_TAGS_NOT_SUPPORTED);
        if((val & BSN_PUSH_TWO_TAGS_SUPPORTED_VAL) != 0)
            set.add(OFBsnPushTwoTagsMode.BSN_PUSH_TWO_TAGS_SUPPORTED);
        return Collections.unmodifiableSet(set);
    }

    public static byte toWireValue(Set<OFBsnPushTwoTagsMode> set) {
        byte wireValue = 0;

        for(OFBsnPushTwoTagsMode e: set) {
            switch(e) {
                case BSN_PUSH_TWO_TAGS_NOT_SUPPORTED:
                    wireValue |= BSN_PUSH_TWO_TAGS_NOT_SUPPORTED_VAL;
                    break;
                case BSN_PUSH_TWO_TAGS_SUPPORTED:
                    wireValue |= BSN_PUSH_TWO_TAGS_SUPPORTED_VAL;
                    break;
                default:
                    throw new IllegalArgumentException("Illegal enum value for type OFBsnPushTwoTagsMode in version 1.4: " + e);
            }
        }
        return wireValue;
    }

}
