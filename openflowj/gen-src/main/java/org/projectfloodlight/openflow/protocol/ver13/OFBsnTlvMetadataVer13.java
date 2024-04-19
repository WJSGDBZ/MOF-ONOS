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

class OFBsnTlvMetadataVer13 implements OFBsnTlvMetadata {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvMetadataVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 6;


    // OF message fields
    private final OFBsnMetadata value;
//

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvMetadataVer13(OFBsnMetadata value) {
        if(value == null) {
            throw new NullPointerException("OFBsnTlvMetadataVer13: property value cannot be null");
        }
        this.value = value;
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0xdd;
    }

    @Override
    public OFBsnMetadata getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFBsnTlvMetadata.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvMetadata.Builder {
        final OFBsnTlvMetadataVer13 parentMessage;

        // OF message fields
        private boolean valueSet;
        private OFBsnMetadata value;

        BuilderWithParent(OFBsnTlvMetadataVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0xdd;
    }

    @Override
    public OFBsnMetadata getValue() {
        return value;
    }

    @Override
    public OFBsnTlvMetadata.Builder setValue(OFBsnMetadata value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFBsnTlvMetadata build() {
                OFBsnMetadata value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");

                //
                return new OFBsnTlvMetadataVer13(
                    value
                );
        }

    }

    static class Builder implements OFBsnTlvMetadata.Builder {
        // OF message fields
        private boolean valueSet;
        private OFBsnMetadata value;

    @Override
    public int getType() {
        return 0xdd;
    }

    @Override
    public OFBsnMetadata getValue() {
        return value;
    }

    @Override
    public OFBsnTlvMetadata.Builder setValue(OFBsnMetadata value) {
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
        public OFBsnTlvMetadata build() {
            if(!this.valueSet)
                throw new IllegalStateException("Property value doesn't have default value -- must be set");
            if(value == null)
                throw new NullPointerException("Property value must not be null");


            return new OFBsnTlvMetadataVer13(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvMetadata> {
        @Override
        public OFBsnTlvMetadata readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0xdd
            short type = bb.readShort();
            if(type != (short) 0xdd)
                throw new OFParseError("Wrong type: Expected=0xdd(0xdd), got="+type);
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
            OFBsnMetadata value = OFBsnMetadataSerializerVer13.readFrom(bb);

            OFBsnTlvMetadataVer13 bsnTlvMetadataVer13 = new OFBsnTlvMetadataVer13(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvMetadataVer13);
            return bsnTlvMetadataVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvMetadataVer13Funnel FUNNEL = new OFBsnTlvMetadataVer13Funnel();
    static class OFBsnTlvMetadataVer13Funnel implements Funnel<OFBsnTlvMetadataVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvMetadataVer13 message, PrimitiveSink sink) {
            // fixed value property type = 0xdd
            sink.putShort((short) 0xdd);
            // fixed value property length = 6
            sink.putShort((short) 0x6);
            OFBsnMetadataSerializerVer13.putTo(message.value, sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvMetadataVer13> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvMetadataVer13 message) {
            // fixed value property type = 0xdd
            bb.writeShort((short) 0xdd);
            // fixed value property length = 6
            bb.writeShort((short) 0x6);
            OFBsnMetadataSerializerVer13.writeTo(bb, message.value);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvMetadataVer13(");
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
        OFBsnTlvMetadataVer13 other = (OFBsnTlvMetadataVer13) obj;

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