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

class OFBsnGentableClearReplyVer15 implements OFBsnGentableClearReply {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnGentableClearReplyVer15.class);
    // version: 1.5
    final static byte WIRE_VERSION = 6;
    final static int LENGTH = 28;

        private final static long DEFAULT_XID = 0x0L;
        private final static long DEFAULT_DELETED_COUNT = 0x0L;
        private final static long DEFAULT_ERROR_COUNT = 0x0L;

    // OF message fields
    private final long xid;
    private final GenTableId tableId;
    private final long deletedCount;
    private final long errorCount;
//

    // package private constructor - used by readers, builders, and factory
    OFBsnGentableClearReplyVer15(long xid, GenTableId tableId, long deletedCount, long errorCount) {
        if(tableId == null) {
            throw new NullPointerException("OFBsnGentableClearReplyVer15: property tableId cannot be null");
        }
        this.xid = U32.normalize(xid);
        this.tableId = tableId;
        this.deletedCount = U32.normalize(deletedCount);
        this.errorCount = U32.normalize(errorCount);
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
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
        return 0x31L;
    }

    @Override
    public GenTableId getTableId() {
        return tableId;
    }

    @Override
    public long getDeletedCount() {
        return deletedCount;
    }

    @Override
    public long getErrorCount() {
        return errorCount;
    }



    public OFBsnGentableClearReply.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnGentableClearReply.Builder {
        final OFBsnGentableClearReplyVer15 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean tableIdSet;
        private GenTableId tableId;
        private boolean deletedCountSet;
        private long deletedCount;
        private boolean errorCountSet;
        private long errorCount;

        BuilderWithParent(OFBsnGentableClearReplyVer15 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
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
    public OFBsnGentableClearReply.Builder setXid(long xid) {
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
        return 0x31L;
    }

    @Override
    public GenTableId getTableId() {
        return tableId;
    }

    @Override
    public OFBsnGentableClearReply.Builder setTableId(GenTableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public long getDeletedCount() {
        return deletedCount;
    }

    @Override
    public OFBsnGentableClearReply.Builder setDeletedCount(long deletedCount) {
        this.deletedCount = deletedCount;
        this.deletedCountSet = true;
        return this;
    }
    @Override
    public long getErrorCount() {
        return errorCount;
    }

    @Override
    public OFBsnGentableClearReply.Builder setErrorCount(long errorCount) {
        this.errorCount = errorCount;
        this.errorCountSet = true;
        return this;
    }


        @Override
        public OFBsnGentableClearReply build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                GenTableId tableId = this.tableIdSet ? this.tableId : parentMessage.tableId;
                if(tableId == null)
                    throw new NullPointerException("Property tableId must not be null");
                long deletedCount = this.deletedCountSet ? this.deletedCount : parentMessage.deletedCount;
                long errorCount = this.errorCountSet ? this.errorCount : parentMessage.errorCount;

                //
                return new OFBsnGentableClearReplyVer15(
                    xid,
                    tableId,
                    deletedCount,
                    errorCount
                );
        }

    }

    static class Builder implements OFBsnGentableClearReply.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean tableIdSet;
        private GenTableId tableId;
        private boolean deletedCountSet;
        private long deletedCount;
        private boolean errorCountSet;
        private long errorCount;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
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
    public OFBsnGentableClearReply.Builder setXid(long xid) {
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
        return 0x31L;
    }

    @Override
    public GenTableId getTableId() {
        return tableId;
    }

    @Override
    public OFBsnGentableClearReply.Builder setTableId(GenTableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public long getDeletedCount() {
        return deletedCount;
    }

    @Override
    public OFBsnGentableClearReply.Builder setDeletedCount(long deletedCount) {
        this.deletedCount = deletedCount;
        this.deletedCountSet = true;
        return this;
    }
    @Override
    public long getErrorCount() {
        return errorCount;
    }

    @Override
    public OFBsnGentableClearReply.Builder setErrorCount(long errorCount) {
        this.errorCount = errorCount;
        this.errorCountSet = true;
        return this;
    }
//
        @Override
        public OFBsnGentableClearReply build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            if(!this.tableIdSet)
                throw new IllegalStateException("Property tableId doesn't have default value -- must be set");
            if(tableId == null)
                throw new NullPointerException("Property tableId must not be null");
            long deletedCount = this.deletedCountSet ? this.deletedCount : DEFAULT_DELETED_COUNT;
            long errorCount = this.errorCountSet ? this.errorCount : DEFAULT_ERROR_COUNT;


            return new OFBsnGentableClearReplyVer15(
                    xid,
                    tableId,
                    deletedCount,
                    errorCount
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnGentableClearReply> {
        @Override
        public OFBsnGentableClearReply readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 6
            byte version = bb.readByte();
            if(version != (byte) 0x6)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_15(6), got="+version);
            // fixed value property type == 4
            byte type = bb.readByte();
            if(type != (byte) 0x4)
                throw new OFParseError("Wrong type: Expected=OFType.EXPERIMENTER(4), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 28)
                throw new OFParseError("Wrong length: Expected=28(28), got="+length);
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
            // fixed value property subtype == 0x31L
            int subtype = bb.readInt();
            if(subtype != 0x31)
                throw new OFParseError("Wrong subtype: Expected=0x31L(0x31L), got="+subtype);
            GenTableId tableId = GenTableId.read2Bytes(bb);
            // pad: 2 bytes
            bb.skipBytes(2);
            long deletedCount = U32.f(bb.readInt());
            long errorCount = U32.f(bb.readInt());

            OFBsnGentableClearReplyVer15 bsnGentableClearReplyVer15 = new OFBsnGentableClearReplyVer15(
                    xid,
                      tableId,
                      deletedCount,
                      errorCount
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnGentableClearReplyVer15);
            return bsnGentableClearReplyVer15;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnGentableClearReplyVer15Funnel FUNNEL = new OFBsnGentableClearReplyVer15Funnel();
    static class OFBsnGentableClearReplyVer15Funnel implements Funnel<OFBsnGentableClearReplyVer15> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnGentableClearReplyVer15 message, PrimitiveSink sink) {
            // fixed value property version = 6
            sink.putByte((byte) 0x6);
            // fixed value property type = 4
            sink.putByte((byte) 0x4);
            // fixed value property length = 28
            sink.putShort((short) 0x1c);
            sink.putLong(message.xid);
            // fixed value property experimenter = 0x5c16c7L
            sink.putInt(0x5c16c7);
            // fixed value property subtype = 0x31L
            sink.putInt(0x31);
            message.tableId.putTo(sink);
            // skip pad (2 bytes)
            sink.putLong(message.deletedCount);
            sink.putLong(message.errorCount);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnGentableClearReplyVer15> {
        @Override
        public void write(ByteBuf bb, OFBsnGentableClearReplyVer15 message) {
            // fixed value property version = 6
            bb.writeByte((byte) 0x6);
            // fixed value property type = 4
            bb.writeByte((byte) 0x4);
            // fixed value property length = 28
            bb.writeShort((short) 0x1c);
            bb.writeInt(U32.t(message.xid));
            // fixed value property experimenter = 0x5c16c7L
            bb.writeInt(0x5c16c7);
            // fixed value property subtype = 0x31L
            bb.writeInt(0x31);
            message.tableId.write2Bytes(bb);
            // pad: 2 bytes
            bb.writeZero(2);
            bb.writeInt(U32.t(message.deletedCount));
            bb.writeInt(U32.t(message.errorCount));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnGentableClearReplyVer15(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("tableId=").append(tableId);
        b.append(", ");
        b.append("deletedCount=").append(deletedCount);
        b.append(", ");
        b.append("errorCount=").append(errorCount);
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
        OFBsnGentableClearReplyVer15 other = (OFBsnGentableClearReplyVer15) obj;

        if( xid != other.xid)
            return false;
        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if( deletedCount != other.deletedCount)
            return false;
        if( errorCount != other.errorCount)
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
        OFBsnGentableClearReplyVer15 other = (OFBsnGentableClearReplyVer15) obj;

        // ignore XID
        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if( deletedCount != other.deletedCount)
            return false;
        if( errorCount != other.errorCount)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime *  (int) (deletedCount ^ (deletedCount >>> 32));
        result = prime *  (int) (errorCount ^ (errorCount >>> 32));
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime *  (int) (deletedCount ^ (deletedCount >>> 32));
        result = prime *  (int) (errorCount ^ (errorCount >>> 32));
        return result;
    }

}
