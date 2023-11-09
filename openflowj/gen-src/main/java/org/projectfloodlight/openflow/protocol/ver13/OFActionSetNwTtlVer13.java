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
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFActionSetNwTtlVer13 implements OFActionSetNwTtl {
    private static final Logger logger = LoggerFactory.getLogger(OFActionSetNwTtlVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 8;

        private final static short DEFAULT_NW_TTL = (short) 0x0;

    // OF message fields
    private final short nwTtl;
//
    // Immutable default instance
    final static OFActionSetNwTtlVer13 DEFAULT = new OFActionSetNwTtlVer13(
        DEFAULT_NW_TTL
    );

    // package private constructor - used by readers, builders, and factory
    OFActionSetNwTtlVer13(short nwTtl) {
        this.nwTtl = U8.normalize(nwTtl);
    }

    // Accessors for OF message fields
    @Override
    public OFActionType getType() {
        return OFActionType.SET_NW_TTL;
    }

    @Override
    public short getNwTtl() {
        return nwTtl;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFActionSetNwTtl.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFActionSetNwTtl.Builder {
        final OFActionSetNwTtlVer13 parentMessage;

        // OF message fields
        private boolean nwTtlSet;
        private short nwTtl;

        BuilderWithParent(OFActionSetNwTtlVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFActionType getType() {
        return OFActionType.SET_NW_TTL;
    }

    @Override
    public short getNwTtl() {
        return nwTtl;
    }

    @Override
    public OFActionSetNwTtl.Builder setNwTtl(short nwTtl) {
        this.nwTtl = nwTtl;
        this.nwTtlSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFActionSetNwTtl build() {
                short nwTtl = this.nwTtlSet ? this.nwTtl : parentMessage.nwTtl;

                //
                return new OFActionSetNwTtlVer13(
                    nwTtl
                );
        }

    }

    static class Builder implements OFActionSetNwTtl.Builder {
        // OF message fields
        private boolean nwTtlSet;
        private short nwTtl;

    @Override
    public OFActionType getType() {
        return OFActionType.SET_NW_TTL;
    }

    @Override
    public short getNwTtl() {
        return nwTtl;
    }

    @Override
    public OFActionSetNwTtl.Builder setNwTtl(short nwTtl) {
        this.nwTtl = nwTtl;
        this.nwTtlSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFActionSetNwTtl build() {
            short nwTtl = this.nwTtlSet ? this.nwTtl : DEFAULT_NW_TTL;


            return new OFActionSetNwTtlVer13(
                    nwTtl
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFActionSetNwTtl> {
        @Override
        public OFActionSetNwTtl readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 23
            short type = bb.readShort();
            if(type != (short) 0x17)
                throw new OFParseError("Wrong type: Expected=OFActionType.SET_NW_TTL(23), got="+type);
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
            short nwTtl = U8.f(bb.readByte());
            // pad: 3 bytes
            bb.skipBytes(3);

            OFActionSetNwTtlVer13 actionSetNwTtlVer13 = new OFActionSetNwTtlVer13(
                    nwTtl
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", actionSetNwTtlVer13);
            return actionSetNwTtlVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFActionSetNwTtlVer13Funnel FUNNEL = new OFActionSetNwTtlVer13Funnel();
    static class OFActionSetNwTtlVer13Funnel implements Funnel<OFActionSetNwTtlVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFActionSetNwTtlVer13 message, PrimitiveSink sink) {
            // fixed value property type = 23
            sink.putShort((short) 0x17);
            // fixed value property length = 8
            sink.putShort((short) 0x8);
            sink.putShort(message.nwTtl);
            // skip pad (3 bytes)
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFActionSetNwTtlVer13> {
        @Override
        public void write(ByteBuf bb, OFActionSetNwTtlVer13 message) {
            // fixed value property type = 23
            bb.writeShort((short) 0x17);
            // fixed value property length = 8
            bb.writeShort((short) 0x8);
            bb.writeByte(U8.t(message.nwTtl));
            // pad: 3 bytes
            bb.writeZero(3);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFActionSetNwTtlVer13(");
        b.append("nwTtl=").append(nwTtl);
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
        OFActionSetNwTtlVer13 other = (OFActionSetNwTtlVer13) obj;

        if( nwTtl != other.nwTtl)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + nwTtl;
        return result;
    }

}
