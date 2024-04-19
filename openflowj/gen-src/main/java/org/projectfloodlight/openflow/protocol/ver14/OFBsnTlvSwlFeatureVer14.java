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

class OFBsnTlvSwlFeatureVer14 implements OFBsnTlvSwlFeature {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvSwlFeatureVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 6;


    // OF message fields
    private final OFBsnSwlFeature value;
//

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvSwlFeatureVer14(OFBsnSwlFeature value) {
        if(value == null) {
            throw new NullPointerException("OFBsnTlvSwlFeatureVer14: property value cannot be null");
        }
        this.value = value;
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0xe4;
    }

    @Override
    public OFBsnSwlFeature getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFBsnTlvSwlFeature.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvSwlFeature.Builder {
        final OFBsnTlvSwlFeatureVer14 parentMessage;

        // OF message fields
        private boolean valueSet;
        private OFBsnSwlFeature value;

        BuilderWithParent(OFBsnTlvSwlFeatureVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0xe4;
    }

    @Override
    public OFBsnSwlFeature getValue() {
        return value;
    }

    @Override
    public OFBsnTlvSwlFeature.Builder setValue(OFBsnSwlFeature value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFBsnTlvSwlFeature build() {
                OFBsnSwlFeature value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");

                //
                return new OFBsnTlvSwlFeatureVer14(
                    value
                );
        }

    }

    static class Builder implements OFBsnTlvSwlFeature.Builder {
        // OF message fields
        private boolean valueSet;
        private OFBsnSwlFeature value;

    @Override
    public int getType() {
        return 0xe4;
    }

    @Override
    public OFBsnSwlFeature getValue() {
        return value;
    }

    @Override
    public OFBsnTlvSwlFeature.Builder setValue(OFBsnSwlFeature value) {
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
        public OFBsnTlvSwlFeature build() {
            if(!this.valueSet)
                throw new IllegalStateException("Property value doesn't have default value -- must be set");
            if(value == null)
                throw new NullPointerException("Property value must not be null");


            return new OFBsnTlvSwlFeatureVer14(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvSwlFeature> {
        @Override
        public OFBsnTlvSwlFeature readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0xe4
            short type = bb.readShort();
            if(type != (short) 0xe4)
                throw new OFParseError("Wrong type: Expected=0xe4(0xe4), got="+type);
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
            OFBsnSwlFeature value = OFBsnSwlFeatureSerializerVer14.readFrom(bb);

            OFBsnTlvSwlFeatureVer14 bsnTlvSwlFeatureVer14 = new OFBsnTlvSwlFeatureVer14(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvSwlFeatureVer14);
            return bsnTlvSwlFeatureVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvSwlFeatureVer14Funnel FUNNEL = new OFBsnTlvSwlFeatureVer14Funnel();
    static class OFBsnTlvSwlFeatureVer14Funnel implements Funnel<OFBsnTlvSwlFeatureVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvSwlFeatureVer14 message, PrimitiveSink sink) {
            // fixed value property type = 0xe4
            sink.putShort((short) 0xe4);
            // fixed value property length = 6
            sink.putShort((short) 0x6);
            OFBsnSwlFeatureSerializerVer14.putTo(message.value, sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvSwlFeatureVer14> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvSwlFeatureVer14 message) {
            // fixed value property type = 0xe4
            bb.writeShort((short) 0xe4);
            // fixed value property length = 6
            bb.writeShort((short) 0x6);
            OFBsnSwlFeatureSerializerVer14.writeTo(bb, message.value);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvSwlFeatureVer14(");
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
        OFBsnTlvSwlFeatureVer14 other = (OFBsnTlvSwlFeatureVer14) obj;

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