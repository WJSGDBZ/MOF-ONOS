// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver15;

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

class OFBsnTlvHashGtpHeaderMatchVer15 implements OFBsnTlvHashGtpHeaderMatch {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvHashGtpHeaderMatchVer15.class);
    // version: 1.5
    final static byte WIRE_VERSION = 6;
    final static int LENGTH = 6;

        private final static short DEFAULT_FIRST_HEADER_BYTE = (short) 0x0;
        private final static short DEFAULT_FIRST_HEADER_MASK = (short) 0x0;

    // OF message fields
    private final short firstHeaderByte;
    private final short firstHeaderMask;
//
    // Immutable default instance
    final static OFBsnTlvHashGtpHeaderMatchVer15 DEFAULT = new OFBsnTlvHashGtpHeaderMatchVer15(
        DEFAULT_FIRST_HEADER_BYTE, DEFAULT_FIRST_HEADER_MASK
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvHashGtpHeaderMatchVer15(short firstHeaderByte, short firstHeaderMask) {
        this.firstHeaderByte = U8.normalize(firstHeaderByte);
        this.firstHeaderMask = U8.normalize(firstHeaderMask);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x68;
    }

    @Override
    public short getFirstHeaderByte() {
        return firstHeaderByte;
    }

    @Override
    public short getFirstHeaderMask() {
        return firstHeaderMask;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



    public OFBsnTlvHashGtpHeaderMatch.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvHashGtpHeaderMatch.Builder {
        final OFBsnTlvHashGtpHeaderMatchVer15 parentMessage;

        // OF message fields
        private boolean firstHeaderByteSet;
        private short firstHeaderByte;
        private boolean firstHeaderMaskSet;
        private short firstHeaderMask;

        BuilderWithParent(OFBsnTlvHashGtpHeaderMatchVer15 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x68;
    }

    @Override
    public short getFirstHeaderByte() {
        return firstHeaderByte;
    }

    @Override
    public OFBsnTlvHashGtpHeaderMatch.Builder setFirstHeaderByte(short firstHeaderByte) {
        this.firstHeaderByte = firstHeaderByte;
        this.firstHeaderByteSet = true;
        return this;
    }
    @Override
    public short getFirstHeaderMask() {
        return firstHeaderMask;
    }

    @Override
    public OFBsnTlvHashGtpHeaderMatch.Builder setFirstHeaderMask(short firstHeaderMask) {
        this.firstHeaderMask = firstHeaderMask;
        this.firstHeaderMaskSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



        @Override
        public OFBsnTlvHashGtpHeaderMatch build() {
                short firstHeaderByte = this.firstHeaderByteSet ? this.firstHeaderByte : parentMessage.firstHeaderByte;
                short firstHeaderMask = this.firstHeaderMaskSet ? this.firstHeaderMask : parentMessage.firstHeaderMask;

                //
                return new OFBsnTlvHashGtpHeaderMatchVer15(
                    firstHeaderByte,
                    firstHeaderMask
                );
        }

    }

    static class Builder implements OFBsnTlvHashGtpHeaderMatch.Builder {
        // OF message fields
        private boolean firstHeaderByteSet;
        private short firstHeaderByte;
        private boolean firstHeaderMaskSet;
        private short firstHeaderMask;

    @Override
    public int getType() {
        return 0x68;
    }

    @Override
    public short getFirstHeaderByte() {
        return firstHeaderByte;
    }

    @Override
    public OFBsnTlvHashGtpHeaderMatch.Builder setFirstHeaderByte(short firstHeaderByte) {
        this.firstHeaderByte = firstHeaderByte;
        this.firstHeaderByteSet = true;
        return this;
    }
    @Override
    public short getFirstHeaderMask() {
        return firstHeaderMask;
    }

    @Override
    public OFBsnTlvHashGtpHeaderMatch.Builder setFirstHeaderMask(short firstHeaderMask) {
        this.firstHeaderMask = firstHeaderMask;
        this.firstHeaderMaskSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }

//
        @Override
        public OFBsnTlvHashGtpHeaderMatch build() {
            short firstHeaderByte = this.firstHeaderByteSet ? this.firstHeaderByte : DEFAULT_FIRST_HEADER_BYTE;
            short firstHeaderMask = this.firstHeaderMaskSet ? this.firstHeaderMask : DEFAULT_FIRST_HEADER_MASK;


            return new OFBsnTlvHashGtpHeaderMatchVer15(
                    firstHeaderByte,
                    firstHeaderMask
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvHashGtpHeaderMatch> {
        @Override
        public OFBsnTlvHashGtpHeaderMatch readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x68
            short type = bb.readShort();
            if(type != (short) 0x68)
                throw new OFParseError("Wrong type: Expected=0x68(0x68), got="+type);
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
            short firstHeaderByte = U8.f(bb.readByte());
            short firstHeaderMask = U8.f(bb.readByte());

            OFBsnTlvHashGtpHeaderMatchVer15 bsnTlvHashGtpHeaderMatchVer15 = new OFBsnTlvHashGtpHeaderMatchVer15(
                    firstHeaderByte,
                      firstHeaderMask
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvHashGtpHeaderMatchVer15);
            return bsnTlvHashGtpHeaderMatchVer15;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvHashGtpHeaderMatchVer15Funnel FUNNEL = new OFBsnTlvHashGtpHeaderMatchVer15Funnel();
    static class OFBsnTlvHashGtpHeaderMatchVer15Funnel implements Funnel<OFBsnTlvHashGtpHeaderMatchVer15> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvHashGtpHeaderMatchVer15 message, PrimitiveSink sink) {
            // fixed value property type = 0x68
            sink.putShort((short) 0x68);
            // fixed value property length = 6
            sink.putShort((short) 0x6);
            sink.putShort(message.firstHeaderByte);
            sink.putShort(message.firstHeaderMask);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvHashGtpHeaderMatchVer15> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvHashGtpHeaderMatchVer15 message) {
            // fixed value property type = 0x68
            bb.writeShort((short) 0x68);
            // fixed value property length = 6
            bb.writeShort((short) 0x6);
            bb.writeByte(U8.t(message.firstHeaderByte));
            bb.writeByte(U8.t(message.firstHeaderMask));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvHashGtpHeaderMatchVer15(");
        b.append("firstHeaderByte=").append(firstHeaderByte);
        b.append(", ");
        b.append("firstHeaderMask=").append(firstHeaderMask);
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
        OFBsnTlvHashGtpHeaderMatchVer15 other = (OFBsnTlvHashGtpHeaderMatchVer15) obj;

        if( firstHeaderByte != other.firstHeaderByte)
            return false;
        if( firstHeaderMask != other.firstHeaderMask)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + firstHeaderByte;
        result = prime * result + firstHeaderMask;
        return result;
    }

}
