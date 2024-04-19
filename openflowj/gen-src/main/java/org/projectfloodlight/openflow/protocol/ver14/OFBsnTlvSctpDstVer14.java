// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Set;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFBsnTlvSctpDstVer14 implements OFBsnTlvSctpDst {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvSctpDstVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 6;

        private final static int DEFAULT_VALUE = 0x0;

    // OF message fields
    private final int value;
//
    // Immutable default instance
    final static OFBsnTlvSctpDstVer14 DEFAULT = new OFBsnTlvSctpDstVer14(
        DEFAULT_VALUE
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvSctpDstVer14(int value) {
        this.value = U16.normalize(value);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0xcb;
    }

    @Override
    public int getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFBsnTlvSctpDst.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvSctpDst.Builder {
        final OFBsnTlvSctpDstVer14 parentMessage;

        // OF message fields
        private boolean valueSet;
        private int value;

        BuilderWithParent(OFBsnTlvSctpDstVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0xcb;
    }

    @Override
    public int getValue() {
        return value;
    }

    @Override
    public OFBsnTlvSctpDst.Builder setValue(int value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFBsnTlvSctpDst build() {
                int value = this.valueSet ? this.value : parentMessage.value;

                //
                return new OFBsnTlvSctpDstVer14(
                    value
                );
        }

    }

    static class Builder implements OFBsnTlvSctpDst.Builder {
        // OF message fields
        private boolean valueSet;
        private int value;

    @Override
    public int getType() {
        return 0xcb;
    }

    @Override
    public int getValue() {
        return value;
    }

    @Override
    public OFBsnTlvSctpDst.Builder setValue(int value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFBsnTlvSctpDst build() {
            int value = this.valueSet ? this.value : DEFAULT_VALUE;


            return new OFBsnTlvSctpDstVer14(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvSctpDst> {
        @Override
        public OFBsnTlvSctpDst readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0xcb
            short type = bb.readShort();
            if(type != (short) 0xcb)
                throw new OFParseError("Wrong type: Expected=0xcb(0xcb), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 6)
                throw new OFParseError("Wrong length: Expected=6(6), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            int value = U16.f(bb.readShort());

            OFBsnTlvSctpDstVer14 bsnTlvSctpDstVer14 = new OFBsnTlvSctpDstVer14(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvSctpDstVer14);
            return bsnTlvSctpDstVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvSctpDstVer14Funnel FUNNEL = new OFBsnTlvSctpDstVer14Funnel();
    static class OFBsnTlvSctpDstVer14Funnel implements Funnel<OFBsnTlvSctpDstVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvSctpDstVer14 message, PrimitiveSink sink) {
            // fixed value property type = 0xcb
            sink.putShort((short) 0xcb);
            // fixed value property length = 6
            sink.putShort((short) 0x6);
            sink.putInt(message.value);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvSctpDstVer14> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvSctpDstVer14 message) {
            // fixed value property type = 0xcb
            bb.writeShort((short) 0xcb);
            // fixed value property length = 6
            bb.writeShort((short) 0x6);
            bb.writeShort(U16.t(message.value));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvSctpDstVer14(");
        b.append("value=").append(value);
        b.append(")");
        return b.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        OFBsnTlvSctpDstVer14 other = (OFBsnTlvSctpDstVer14) obj;

        if( value != other.value)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + value;
        return result;
    }

}