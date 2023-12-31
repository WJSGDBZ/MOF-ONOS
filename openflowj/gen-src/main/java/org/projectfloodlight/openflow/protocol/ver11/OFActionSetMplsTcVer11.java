// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver11;

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

class OFActionSetMplsTcVer11 implements OFActionSetMplsTc {
    private static final Logger logger = LoggerFactory.getLogger(OFActionSetMplsTcVer11.class);
    // version: 1.1
    final static byte WIRE_VERSION = 2;
    final static int LENGTH = 8;

        private final static short DEFAULT_MPLS_TC = (short) 0x0;

    // OF message fields
    private final short mplsTc;
//
    // Immutable default instance
    final static OFActionSetMplsTcVer11 DEFAULT = new OFActionSetMplsTcVer11(
        DEFAULT_MPLS_TC
    );

    // package private constructor - used by readers, builders, and factory
    OFActionSetMplsTcVer11(short mplsTc) {
        this.mplsTc = U8.normalize(mplsTc);
    }

    // Accessors for OF message fields
    @Override
    public OFActionType getType() {
        return OFActionType.SET_MPLS_TC;
    }

    @Override
    public short getMplsTc() {
        return mplsTc;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }



    public OFActionSetMplsTc.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFActionSetMplsTc.Builder {
        final OFActionSetMplsTcVer11 parentMessage;

        // OF message fields
        private boolean mplsTcSet;
        private short mplsTc;

        BuilderWithParent(OFActionSetMplsTcVer11 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFActionType getType() {
        return OFActionType.SET_MPLS_TC;
    }

    @Override
    public short getMplsTc() {
        return mplsTc;
    }

    @Override
    public OFActionSetMplsTc.Builder setMplsTc(short mplsTc) {
        this.mplsTc = mplsTc;
        this.mplsTcSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }



        @Override
        public OFActionSetMplsTc build() {
                short mplsTc = this.mplsTcSet ? this.mplsTc : parentMessage.mplsTc;

                //
                return new OFActionSetMplsTcVer11(
                    mplsTc
                );
        }

    }

    static class Builder implements OFActionSetMplsTc.Builder {
        // OF message fields
        private boolean mplsTcSet;
        private short mplsTc;

    @Override
    public OFActionType getType() {
        return OFActionType.SET_MPLS_TC;
    }

    @Override
    public short getMplsTc() {
        return mplsTc;
    }

    @Override
    public OFActionSetMplsTc.Builder setMplsTc(short mplsTc) {
        this.mplsTc = mplsTc;
        this.mplsTcSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }

//
        @Override
        public OFActionSetMplsTc build() {
            short mplsTc = this.mplsTcSet ? this.mplsTc : DEFAULT_MPLS_TC;


            return new OFActionSetMplsTcVer11(
                    mplsTc
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFActionSetMplsTc> {
        @Override
        public OFActionSetMplsTc readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 14
            short type = bb.readShort();
            if(type != (short) 0xe)
                throw new OFParseError("Wrong type: Expected=OFActionType.SET_MPLS_TC(14), got="+type);
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
            short mplsTc = U8.f(bb.readByte());
            // pad: 3 bytes
            bb.skipBytes(3);

            OFActionSetMplsTcVer11 actionSetMplsTcVer11 = new OFActionSetMplsTcVer11(
                    mplsTc
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", actionSetMplsTcVer11);
            return actionSetMplsTcVer11;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFActionSetMplsTcVer11Funnel FUNNEL = new OFActionSetMplsTcVer11Funnel();
    static class OFActionSetMplsTcVer11Funnel implements Funnel<OFActionSetMplsTcVer11> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFActionSetMplsTcVer11 message, PrimitiveSink sink) {
            // fixed value property type = 14
            sink.putShort((short) 0xe);
            // fixed value property length = 8
            sink.putShort((short) 0x8);
            sink.putShort(message.mplsTc);
            // skip pad (3 bytes)
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFActionSetMplsTcVer11> {
        @Override
        public void write(ByteBuf bb, OFActionSetMplsTcVer11 message) {
            // fixed value property type = 14
            bb.writeShort((short) 0xe);
            // fixed value property length = 8
            bb.writeShort((short) 0x8);
            bb.writeByte(U8.t(message.mplsTc));
            // pad: 3 bytes
            bb.writeZero(3);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFActionSetMplsTcVer11(");
        b.append("mplsTc=").append(mplsTc);
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
        OFActionSetMplsTcVer11 other = (OFActionSetMplsTcVer11) obj;

        if( mplsTc != other.mplsTc)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + mplsTc;
        return result;
    }

}
