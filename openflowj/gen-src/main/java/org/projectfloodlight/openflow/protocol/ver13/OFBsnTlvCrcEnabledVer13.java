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

class OFBsnTlvCrcEnabledVer13 implements OFBsnTlvCrcEnabled {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvCrcEnabledVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 5;

        private final static short DEFAULT_VALUE = (short) 0x0;

    // OF message fields
    private final short value;
//
    // Immutable default instance
    final static OFBsnTlvCrcEnabledVer13 DEFAULT = new OFBsnTlvCrcEnabledVer13(
        DEFAULT_VALUE
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvCrcEnabledVer13(short value) {
        this.value = U8.normalize(value);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x16;
    }

    @Override
    public short getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFBsnTlvCrcEnabled.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvCrcEnabled.Builder {
        final OFBsnTlvCrcEnabledVer13 parentMessage;

        // OF message fields
        private boolean valueSet;
        private short value;

        BuilderWithParent(OFBsnTlvCrcEnabledVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x16;
    }

    @Override
    public short getValue() {
        return value;
    }

    @Override
    public OFBsnTlvCrcEnabled.Builder setValue(short value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFBsnTlvCrcEnabled build() {
                short value = this.valueSet ? this.value : parentMessage.value;

                //
                return new OFBsnTlvCrcEnabledVer13(
                    value
                );
        }

    }

    static class Builder implements OFBsnTlvCrcEnabled.Builder {
        // OF message fields
        private boolean valueSet;
        private short value;

    @Override
    public int getType() {
        return 0x16;
    }

    @Override
    public short getValue() {
        return value;
    }

    @Override
    public OFBsnTlvCrcEnabled.Builder setValue(short value) {
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
        public OFBsnTlvCrcEnabled build() {
            short value = this.valueSet ? this.value : DEFAULT_VALUE;


            return new OFBsnTlvCrcEnabledVer13(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvCrcEnabled> {
        @Override
        public OFBsnTlvCrcEnabled readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x16
            short type = bb.readShort();
            if(type != (short) 0x16)
                throw new OFParseError("Wrong type: Expected=0x16(0x16), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 5)
                throw new OFParseError("Wrong length: Expected=5(5), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            short value = U8.f(bb.readByte());

            OFBsnTlvCrcEnabledVer13 bsnTlvCrcEnabledVer13 = new OFBsnTlvCrcEnabledVer13(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvCrcEnabledVer13);
            return bsnTlvCrcEnabledVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvCrcEnabledVer13Funnel FUNNEL = new OFBsnTlvCrcEnabledVer13Funnel();
    static class OFBsnTlvCrcEnabledVer13Funnel implements Funnel<OFBsnTlvCrcEnabledVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvCrcEnabledVer13 message, PrimitiveSink sink) {
            // fixed value property type = 0x16
            sink.putShort((short) 0x16);
            // fixed value property length = 5
            sink.putShort((short) 0x5);
            sink.putShort(message.value);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvCrcEnabledVer13> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvCrcEnabledVer13 message) {
            // fixed value property type = 0x16
            bb.writeShort((short) 0x16);
            // fixed value property length = 5
            bb.writeShort((short) 0x5);
            bb.writeByte(U8.t(message.value));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvCrcEnabledVer13(");
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
        OFBsnTlvCrcEnabledVer13 other = (OFBsnTlvCrcEnabledVer13) obj;

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
