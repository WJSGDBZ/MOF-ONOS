// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Set;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFBsnTlvRecordPacketsVer13 implements OFBsnTlvRecordPackets {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvRecordPacketsVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 8;

        private final static long DEFAULT_VALUE = 0x0L;

    // OF message fields
    private final long value;
//
    // Immutable default instance
    final static OFBsnTlvRecordPacketsVer13 DEFAULT = new OFBsnTlvRecordPacketsVer13(
        DEFAULT_VALUE
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvRecordPacketsVer13(long value) {
        this.value = U32.normalize(value);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x9b;
    }

    @Override
    public long getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFBsnTlvRecordPackets.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvRecordPackets.Builder {
        final OFBsnTlvRecordPacketsVer13 parentMessage;

        // OF message fields
        private boolean valueSet;
        private long value;

        BuilderWithParent(OFBsnTlvRecordPacketsVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x9b;
    }

    @Override
    public long getValue() {
        return value;
    }

    @Override
    public OFBsnTlvRecordPackets.Builder setValue(long value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFBsnTlvRecordPackets build() {
                long value = this.valueSet ? this.value : parentMessage.value;

                //
                return new OFBsnTlvRecordPacketsVer13(
                    value
                );
        }

    }

    static class Builder implements OFBsnTlvRecordPackets.Builder {
        // OF message fields
        private boolean valueSet;
        private long value;

    @Override
    public int getType() {
        return 0x9b;
    }

    @Override
    public long getValue() {
        return value;
    }

    @Override
    public OFBsnTlvRecordPackets.Builder setValue(long value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFBsnTlvRecordPackets build() {
            long value = this.valueSet ? this.value : DEFAULT_VALUE;


            return new OFBsnTlvRecordPacketsVer13(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvRecordPackets> {
        @Override
        public OFBsnTlvRecordPackets readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x9b
            short type = bb.readShort();
            if(type != (short) 0x9b)
                throw new OFParseError("Wrong type: Expected=0x9b(0x9b), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 8)
                throw new OFParseError("Wrong length: Expected=8(8), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            long value = U32.f(bb.readInt());

            OFBsnTlvRecordPacketsVer13 bsnTlvRecordPacketsVer13 = new OFBsnTlvRecordPacketsVer13(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvRecordPacketsVer13);
            return bsnTlvRecordPacketsVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvRecordPacketsVer13Funnel FUNNEL = new OFBsnTlvRecordPacketsVer13Funnel();
    static class OFBsnTlvRecordPacketsVer13Funnel implements Funnel<OFBsnTlvRecordPacketsVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvRecordPacketsVer13 message, PrimitiveSink sink) {
            // fixed value property type = 0x9b
            sink.putShort((short) 0x9b);
            // fixed value property length = 8
            sink.putShort((short) 0x8);
            sink.putLong(message.value);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvRecordPacketsVer13> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvRecordPacketsVer13 message) {
            // fixed value property type = 0x9b
            bb.writeShort((short) 0x9b);
            // fixed value property length = 8
            bb.writeShort((short) 0x8);
            bb.writeInt(U32.t(message.value));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvRecordPacketsVer13(");
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
        OFBsnTlvRecordPacketsVer13 other = (OFBsnTlvRecordPacketsVer13) obj;

        if( value != other.value)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (value ^ (value >>> 32));
        return result;
    }

}
