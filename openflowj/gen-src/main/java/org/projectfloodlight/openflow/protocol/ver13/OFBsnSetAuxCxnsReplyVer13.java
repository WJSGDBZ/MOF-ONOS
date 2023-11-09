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

class OFBsnSetAuxCxnsReplyVer13 implements OFBsnSetAuxCxnsReply {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnSetAuxCxnsReplyVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 24;

        private final static long DEFAULT_XID = 0x0L;
        private final static long DEFAULT_NUM_AUX = 0x0L;
        private final static long DEFAULT_STATUS = 0x0L;

    // OF message fields
    private final long xid;
    private final long numAux;
    private final long status;
//
    // Immutable default instance
    final static OFBsnSetAuxCxnsReplyVer13 DEFAULT = new OFBsnSetAuxCxnsReplyVer13(
        DEFAULT_XID, DEFAULT_NUM_AUX, DEFAULT_STATUS
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnSetAuxCxnsReplyVer13(long xid, long numAux, long status) {
        this.xid = U32.normalize(xid);
        this.numAux = U32.normalize(numAux);
        this.status = U32.normalize(status);
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
        return 0x3bL;
    }

    @Override
    public long getNumAux() {
        return numAux;
    }

    @Override
    public long getStatus() {
        return status;
    }



    public OFBsnSetAuxCxnsReply.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnSetAuxCxnsReply.Builder {
        final OFBsnSetAuxCxnsReplyVer13 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean numAuxSet;
        private long numAux;
        private boolean statusSet;
        private long status;

        BuilderWithParent(OFBsnSetAuxCxnsReplyVer13 parentMessage) {
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
    public OFBsnSetAuxCxnsReply.Builder setXid(long xid) {
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
        return 0x3bL;
    }

    @Override
    public long getNumAux() {
        return numAux;
    }

    @Override
    public OFBsnSetAuxCxnsReply.Builder setNumAux(long numAux) {
        this.numAux = numAux;
        this.numAuxSet = true;
        return this;
    }
    @Override
    public long getStatus() {
        return status;
    }

    @Override
    public OFBsnSetAuxCxnsReply.Builder setStatus(long status) {
        this.status = status;
        this.statusSet = true;
        return this;
    }


        @Override
        public OFBsnSetAuxCxnsReply build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                long numAux = this.numAuxSet ? this.numAux : parentMessage.numAux;
                long status = this.statusSet ? this.status : parentMessage.status;

                //
                return new OFBsnSetAuxCxnsReplyVer13(
                    xid,
                    numAux,
                    status
                );
        }

    }

    static class Builder implements OFBsnSetAuxCxnsReply.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean numAuxSet;
        private long numAux;
        private boolean statusSet;
        private long status;

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
    public OFBsnSetAuxCxnsReply.Builder setXid(long xid) {
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
        return 0x3bL;
    }

    @Override
    public long getNumAux() {
        return numAux;
    }

    @Override
    public OFBsnSetAuxCxnsReply.Builder setNumAux(long numAux) {
        this.numAux = numAux;
        this.numAuxSet = true;
        return this;
    }
    @Override
    public long getStatus() {
        return status;
    }

    @Override
    public OFBsnSetAuxCxnsReply.Builder setStatus(long status) {
        this.status = status;
        this.statusSet = true;
        return this;
    }
//
        @Override
        public OFBsnSetAuxCxnsReply build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            long numAux = this.numAuxSet ? this.numAux : DEFAULT_NUM_AUX;
            long status = this.statusSet ? this.status : DEFAULT_STATUS;


            return new OFBsnSetAuxCxnsReplyVer13(
                    xid,
                    numAux,
                    status
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnSetAuxCxnsReply> {
        @Override
        public OFBsnSetAuxCxnsReply readFrom(ByteBuf bb) throws OFParseError {
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
            if(length != 24)
                throw new OFParseError("Wrong length: Expected=24(24), got="+length);
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
            // fixed value property subtype == 0x3bL
            int subtype = bb.readInt();
            if(subtype != 0x3b)
                throw new OFParseError("Wrong subtype: Expected=0x3bL(0x3bL), got="+subtype);
            long numAux = U32.f(bb.readInt());
            long status = U32.f(bb.readInt());

            OFBsnSetAuxCxnsReplyVer13 bsnSetAuxCxnsReplyVer13 = new OFBsnSetAuxCxnsReplyVer13(
                    xid,
                      numAux,
                      status
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnSetAuxCxnsReplyVer13);
            return bsnSetAuxCxnsReplyVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnSetAuxCxnsReplyVer13Funnel FUNNEL = new OFBsnSetAuxCxnsReplyVer13Funnel();
    static class OFBsnSetAuxCxnsReplyVer13Funnel implements Funnel<OFBsnSetAuxCxnsReplyVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnSetAuxCxnsReplyVer13 message, PrimitiveSink sink) {
            // fixed value property version = 4
            sink.putByte((byte) 0x4);
            // fixed value property type = 4
            sink.putByte((byte) 0x4);
            // fixed value property length = 24
            sink.putShort((short) 0x18);
            sink.putLong(message.xid);
            // fixed value property experimenter = 0x5c16c7L
            sink.putInt(0x5c16c7);
            // fixed value property subtype = 0x3bL
            sink.putInt(0x3b);
            sink.putLong(message.numAux);
            sink.putLong(message.status);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnSetAuxCxnsReplyVer13> {
        @Override
        public void write(ByteBuf bb, OFBsnSetAuxCxnsReplyVer13 message) {
            // fixed value property version = 4
            bb.writeByte((byte) 0x4);
            // fixed value property type = 4
            bb.writeByte((byte) 0x4);
            // fixed value property length = 24
            bb.writeShort((short) 0x18);
            bb.writeInt(U32.t(message.xid));
            // fixed value property experimenter = 0x5c16c7L
            bb.writeInt(0x5c16c7);
            // fixed value property subtype = 0x3bL
            bb.writeInt(0x3b);
            bb.writeInt(U32.t(message.numAux));
            bb.writeInt(U32.t(message.status));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnSetAuxCxnsReplyVer13(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("numAux=").append(numAux);
        b.append(", ");
        b.append("status=").append(status);
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
        OFBsnSetAuxCxnsReplyVer13 other = (OFBsnSetAuxCxnsReplyVer13) obj;

        if( xid != other.xid)
            return false;
        if( numAux != other.numAux)
            return false;
        if( status != other.status)
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
        OFBsnSetAuxCxnsReplyVer13 other = (OFBsnSetAuxCxnsReplyVer13) obj;

        // ignore XID
        if( numAux != other.numAux)
            return false;
        if( status != other.status)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime *  (int) (numAux ^ (numAux >>> 32));
        result = prime *  (int) (status ^ (status >>> 32));
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime *  (int) (numAux ^ (numAux >>> 32));
        result = prime *  (int) (status ^ (status >>> 32));
        return result;
    }

}
