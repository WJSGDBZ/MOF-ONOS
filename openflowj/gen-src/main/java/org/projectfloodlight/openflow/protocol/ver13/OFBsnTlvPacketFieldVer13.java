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

class OFBsnTlvPacketFieldVer13 implements OFBsnTlvPacketField {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvPacketFieldVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 6;


    // OF message fields
    private final OFBsnPacketField value;
//

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvPacketFieldVer13(OFBsnPacketField value) {
        if(value == null) {
            throw new NullPointerException("OFBsnTlvPacketFieldVer13: property value cannot be null");
        }
        this.value = value;
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0xde;
    }

    @Override
    public OFBsnPacketField getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFBsnTlvPacketField.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvPacketField.Builder {
        final OFBsnTlvPacketFieldVer13 parentMessage;

        // OF message fields
        private boolean valueSet;
        private OFBsnPacketField value;

        BuilderWithParent(OFBsnTlvPacketFieldVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0xde;
    }

    @Override
    public OFBsnPacketField getValue() {
        return value;
    }

    @Override
    public OFBsnTlvPacketField.Builder setValue(OFBsnPacketField value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFBsnTlvPacketField build() {
                OFBsnPacketField value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");

                //
                return new OFBsnTlvPacketFieldVer13(
                    value
                );
        }

    }

    static class Builder implements OFBsnTlvPacketField.Builder {
        // OF message fields
        private boolean valueSet;
        private OFBsnPacketField value;

    @Override
    public int getType() {
        return 0xde;
    }

    @Override
    public OFBsnPacketField getValue() {
        return value;
    }

    @Override
    public OFBsnTlvPacketField.Builder setValue(OFBsnPacketField value) {
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
        public OFBsnTlvPacketField build() {
            if(!this.valueSet)
                throw new IllegalStateException("Property value doesn't have default value -- must be set");
            if(value == null)
                throw new NullPointerException("Property value must not be null");


            return new OFBsnTlvPacketFieldVer13(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvPacketField> {
        @Override
        public OFBsnTlvPacketField readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0xde
            short type = bb.readShort();
            if(type != (short) 0xde)
                throw new OFParseError("Wrong type: Expected=0xde(0xde), got="+type);
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
            OFBsnPacketField value = OFBsnPacketFieldSerializerVer13.readFrom(bb);

            OFBsnTlvPacketFieldVer13 bsnTlvPacketFieldVer13 = new OFBsnTlvPacketFieldVer13(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvPacketFieldVer13);
            return bsnTlvPacketFieldVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvPacketFieldVer13Funnel FUNNEL = new OFBsnTlvPacketFieldVer13Funnel();
    static class OFBsnTlvPacketFieldVer13Funnel implements Funnel<OFBsnTlvPacketFieldVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvPacketFieldVer13 message, PrimitiveSink sink) {
            // fixed value property type = 0xde
            sink.putShort((short) 0xde);
            // fixed value property length = 6
            sink.putShort((short) 0x6);
            OFBsnPacketFieldSerializerVer13.putTo(message.value, sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvPacketFieldVer13> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvPacketFieldVer13 message) {
            // fixed value property type = 0xde
            bb.writeShort((short) 0xde);
            // fixed value property length = 6
            bb.writeShort((short) 0x6);
            OFBsnPacketFieldSerializerVer13.writeTo(bb, message.value);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvPacketFieldVer13(");
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
        OFBsnTlvPacketFieldVer13 other = (OFBsnTlvPacketFieldVer13) obj;

        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
    }

}
