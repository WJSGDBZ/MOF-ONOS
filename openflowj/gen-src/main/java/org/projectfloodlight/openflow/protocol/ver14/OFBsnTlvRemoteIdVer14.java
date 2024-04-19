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
import java.util.Arrays;

class OFBsnTlvRemoteIdVer14 implements OFBsnTlvRemoteId {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvRemoteIdVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int MINIMUM_LENGTH = 4;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static byte[] DEFAULT_VALUE = new byte[0];

    // OF message fields
    private final byte[] value;
//
    // Immutable default instance
    final static OFBsnTlvRemoteIdVer14 DEFAULT = new OFBsnTlvRemoteIdVer14(
        DEFAULT_VALUE
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvRemoteIdVer14(byte[] value) {
        if(value == null) {
            throw new NullPointerException("OFBsnTlvRemoteIdVer14: property value cannot be null");
        }
        this.value = value;
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0xe0;
    }

    @Override
    public byte[] getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFBsnTlvRemoteId.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvRemoteId.Builder {
        final OFBsnTlvRemoteIdVer14 parentMessage;

        // OF message fields
        private boolean valueSet;
        private byte[] value;

        BuilderWithParent(OFBsnTlvRemoteIdVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0xe0;
    }

    @Override
    public byte[] getValue() {
        return value;
    }

    @Override
    public OFBsnTlvRemoteId.Builder setValue(byte[] value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFBsnTlvRemoteId build() {
                byte[] value = this.valueSet ? this.value : parentMessage.value;
                if(value == null)
                    throw new NullPointerException("Property value must not be null");

                //
                return new OFBsnTlvRemoteIdVer14(
                    value
                );
        }

    }

    static class Builder implements OFBsnTlvRemoteId.Builder {
        // OF message fields
        private boolean valueSet;
        private byte[] value;

    @Override
    public int getType() {
        return 0xe0;
    }

    @Override
    public byte[] getValue() {
        return value;
    }

    @Override
    public OFBsnTlvRemoteId.Builder setValue(byte[] value) {
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
        public OFBsnTlvRemoteId build() {
            byte[] value = this.valueSet ? this.value : DEFAULT_VALUE;
            if(value == null)
                throw new NullPointerException("Property value must not be null");


            return new OFBsnTlvRemoteIdVer14(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvRemoteId> {
        @Override
        public OFBsnTlvRemoteId readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0xe0
            short type = bb.readShort();
            if(type != (short) 0xe0)
                throw new OFParseError("Wrong type: Expected=0xe0(0xe0), got="+type);
            int length = U16.f(bb.readShort());
            if(length < MINIMUM_LENGTH)
                throw new OFParseError("Wrong length: Expected to be >= " + MINIMUM_LENGTH + ", was: " + length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            byte[] value = ChannelUtils.readBytes(bb, length - (bb.readerIndex() - start));

            OFBsnTlvRemoteIdVer14 bsnTlvRemoteIdVer14 = new OFBsnTlvRemoteIdVer14(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvRemoteIdVer14);
            return bsnTlvRemoteIdVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvRemoteIdVer14Funnel FUNNEL = new OFBsnTlvRemoteIdVer14Funnel();
    static class OFBsnTlvRemoteIdVer14Funnel implements Funnel<OFBsnTlvRemoteIdVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvRemoteIdVer14 message, PrimitiveSink sink) {
            // fixed value property type = 0xe0
            sink.putShort((short) 0xe0);
            // FIXME: skip funnel of length
            sink.putBytes(message.value);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvRemoteIdVer14> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvRemoteIdVer14 message) {
            int startIndex = bb.writerIndex();
            // fixed value property type = 0xe0
            bb.writeShort((short) 0xe0);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            bb.writeBytes(message.value);

            // update length field
            int length = bb.writerIndex() - startIndex;
            if (length > MAXIMUM_LENGTH) {
                throw new IllegalArgumentException("OFBsnTlvRemoteIdVer14: message length (" + length + ") exceeds maximum (0xFFFF)");
            }
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvRemoteIdVer14(");
        b.append("value=").append(Arrays.toString(value));
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
        OFBsnTlvRemoteIdVer14 other = (OFBsnTlvRemoteIdVer14) obj;

        if (!Arrays.equals(value, other.value))
                return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + Arrays.hashCode(value);
        return result;
    }

}