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

class OFBsnBwEnableGetRequestVer13 implements OFBsnBwEnableGetRequest {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnBwEnableGetRequestVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 16;

        private final static long DEFAULT_XID = 0x0L;

    // OF message fields
    private final long xid;
//
    // Immutable default instance
    final static OFBsnBwEnableGetRequestVer13 DEFAULT = new OFBsnBwEnableGetRequestVer13(
        DEFAULT_XID
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnBwEnableGetRequestVer13(long xid) {
        this.xid = U32.normalize(xid);
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

    @Override
    public OFType getType() {
        return OFType.EXPERIMENTER;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public long getExperimenter() {
        return 0x5c16c7L;
    }

    @Override
    public long getSubtype() {
        return 0x13L;
    }



    public OFBsnBwEnableGetRequest.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnBwEnableGetRequest.Builder {
        final OFBsnBwEnableGetRequestVer13 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;

        BuilderWithParent(OFBsnBwEnableGetRequestVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

    @Override
    public OFType getType() {
        return OFType.EXPERIMENTER;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFBsnBwEnableGetRequest.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public long getExperimenter() {
        return 0x5c16c7L;
    }

    @Override
    public long getSubtype() {
        return 0x13L;
    }



        @Override
        public OFBsnBwEnableGetRequest build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;

                //
                return new OFBsnBwEnableGetRequestVer13(
                    xid
                );
        }

    }

    static class Builder implements OFBsnBwEnableGetRequest.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

    @Override
    public OFType getType() {
        return OFType.EXPERIMENTER;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFBsnBwEnableGetRequest.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public long getExperimenter() {
        return 0x5c16c7L;
    }

    @Override
    public long getSubtype() {
        return 0x13L;
    }

//
        @Override
        public OFBsnBwEnableGetRequest build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;


            return new OFBsnBwEnableGetRequestVer13(
                    xid
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnBwEnableGetRequest> {
        @Override
        public OFBsnBwEnableGetRequest readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 4
            byte version = bb.readByte();
            if(version != (byte) 0x4)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_13(4), got="+version);
            // fixed value property type == 4
            byte type = bb.readByte();
            if(type != (byte) 0x4)
                throw new OFParseError("Wrong type: Expected=OFType.EXPERIMENTER(4), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 16)
                throw new OFParseError("Wrong length: Expected=16(16), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            long xid = U32.f(bb.readInt());
            // fixed value property experimenter == 0x5c16c7L
            int experimenter = bb.readInt();
            if(experimenter != 0x5c16c7)
                throw new OFParseError("Wrong experimenter: Expected=0x5c16c7L(0x5c16c7L), got="+experimenter);
            // fixed value property subtype == 0x13L
            int subtype = bb.readInt();
            if(subtype != 0x13)
                throw new OFParseError("Wrong subtype: Expected=0x13L(0x13L), got="+subtype);

            OFBsnBwEnableGetRequestVer13 bsnBwEnableGetRequestVer13 = new OFBsnBwEnableGetRequestVer13(
                    xid
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnBwEnableGetRequestVer13);
            return bsnBwEnableGetRequestVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnBwEnableGetRequestVer13Funnel FUNNEL = new OFBsnBwEnableGetRequestVer13Funnel();
    static class OFBsnBwEnableGetRequestVer13Funnel implements Funnel<OFBsnBwEnableGetRequestVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnBwEnableGetRequestVer13 message, PrimitiveSink sink) {
            // fixed value property version = 4
            sink.putByte((byte) 0x4);
            // fixed value property type = 4
            sink.putByte((byte) 0x4);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            sink.putLong(message.xid);
            // fixed value property experimenter = 0x5c16c7L
            sink.putInt(0x5c16c7);
            // fixed value property subtype = 0x13L
            sink.putInt(0x13);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnBwEnableGetRequestVer13> {
        @Override
        public void write(ByteBuf bb, OFBsnBwEnableGetRequestVer13 message) {
            // fixed value property version = 4
            bb.writeByte((byte) 0x4);
            // fixed value property type = 4
            bb.writeByte((byte) 0x4);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            bb.writeInt(U32.t(message.xid));
            // fixed value property experimenter = 0x5c16c7L
            bb.writeInt(0x5c16c7);
            // fixed value property subtype = 0x13L
            bb.writeInt(0x13);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnBwEnableGetRequestVer13(");
        b.append("xid=").append(xid);
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
        OFBsnBwEnableGetRequestVer13 other = (OFBsnBwEnableGetRequestVer13) obj;

        if( xid != other.xid)
            return false;
        return true;
    }

    @Override
    public boolean equalsIgnoreXid(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        OFBsnBwEnableGetRequestVer13 other = (OFBsnBwEnableGetRequestVer13) obj;

        // ignore XID
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        return result;
    }

}
