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

class OFBsnTlvPortModeVer13 implements OFBsnTlvPortMode {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvPortModeVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 6;


    // OF message fields
    private final OFBsnPortMode value;
//

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvPortModeVer13(OFBsnPortMode value) {
        if(value == null) {
            throw new NullPointerException("OFBsnTlvPortModeVer13: property value cannot be null");
        }
        this.value = value;
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0xb3;
    }

    @Override
    public OFBsnPortMode getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFBsnTlvPortMode.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvPortMode.Builder {
        final OFBsnTlvPortModeVer13 parentMessage;

        // OF message fields
        private boolean valueSet;
        private OFBsnPortMode value;

        BuilderWithParent(OFBsnTlvPortModeVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0xb3;
    }

    @Override
    public OFBsnPortMode getValue() {
        return value;
    }

    @Override
    public OFBsnTlvPortMode.Builder setValue(OFBsnPortMode value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFBsnTlvPortMode build() {
                OFBsnPortMode value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");

                //
                return new OFBsnTlvPortModeVer13(
                    value
                );
        }

    }

    static class Builder implements OFBsnTlvPortMode.Builder {
        // OF message fields
        private boolean valueSet;
        private OFBsnPortMode value;

    @Override
    public int getType() {
        return 0xb3;
    }

    @Override
    public OFBsnPortMode getValue() {
        return value;
    }

    @Override
    public OFBsnTlvPortMode.Builder setValue(OFBsnPortMode value) {
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
        public OFBsnTlvPortMode build() {
            if(!this.valueSet)
                throw new IllegalStateException("Property value doesn't have default value -- must be set");
            if(value == null)
                throw new NullPointerException("Property value must not be null");


            return new OFBsnTlvPortModeVer13(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvPortMode> {
        @Override
        public OFBsnTlvPortMode readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0xb3
            short type = bb.readShort();
            if(type != (short) 0xb3)
                throw new OFParseError("Wrong type: Expected=0xb3(0xb3), got="+type);
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
            OFBsnPortMode value = OFBsnPortModeSerializerVer13.readFrom(bb);

            OFBsnTlvPortModeVer13 bsnTlvPortModeVer13 = new OFBsnTlvPortModeVer13(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvPortModeVer13);
            return bsnTlvPortModeVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvPortModeVer13Funnel FUNNEL = new OFBsnTlvPortModeVer13Funnel();
    static class OFBsnTlvPortModeVer13Funnel implements Funnel<OFBsnTlvPortModeVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvPortModeVer13 message, PrimitiveSink sink) {
            // fixed value property type = 0xb3
            sink.putShort((short) 0xb3);
            // fixed value property length = 6
            sink.putShort((short) 0x6);
            OFBsnPortModeSerializerVer13.putTo(message.value, sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvPortModeVer13> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvPortModeVer13 message) {
            // fixed value property type = 0xb3
            bb.writeShort((short) 0xb3);
            // fixed value property length = 6
            bb.writeShort((short) 0x6);
            OFBsnPortModeSerializerVer13.writeTo(bb, message.value);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvPortModeVer13(");
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
        OFBsnTlvPortModeVer13 other = (OFBsnTlvPortModeVer13) obj;

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
