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

class OFBsnGentableSetBucketsSizeVer13 implements OFBsnGentableSetBucketsSize {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnGentableSetBucketsSizeVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 24;

        private final static long DEFAULT_XID = 0x0L;
        private final static long DEFAULT_BUCKETS_SIZE = 0x0L;

    // OF message fields
    private final long xid;
    private final GenTableId tableId;
    private final long bucketsSize;
//

    // package private constructor - used by readers, builders, and factory
    OFBsnGentableSetBucketsSizeVer13(long xid, GenTableId tableId, long bucketsSize) {
        if(tableId == null) {
            throw new NullPointerException("OFBsnGentableSetBucketsSizeVer13: property tableId cannot be null");
        }
        this.xid = U32.normalize(xid);
        this.tableId = tableId;
        this.bucketsSize = U32.normalize(bucketsSize);
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
        return 0x32L;
    }

    @Override
    public GenTableId getTableId() {
        return tableId;
    }

    @Override
    public long getBucketsSize() {
        return bucketsSize;
    }



    public OFBsnGentableSetBucketsSize.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnGentableSetBucketsSize.Builder {
        final OFBsnGentableSetBucketsSizeVer13 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean tableIdSet;
        private GenTableId tableId;
        private boolean bucketsSizeSet;
        private long bucketsSize;

        BuilderWithParent(OFBsnGentableSetBucketsSizeVer13 parentMessage) {
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
    public OFBsnGentableSetBucketsSize.Builder setXid(long xid) {
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
        return 0x32L;
    }

    @Override
    public GenTableId getTableId() {
        return tableId;
    }

    @Override
    public OFBsnGentableSetBucketsSize.Builder setTableId(GenTableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public long getBucketsSize() {
        return bucketsSize;
    }

    @Override
    public OFBsnGentableSetBucketsSize.Builder setBucketsSize(long bucketsSize) {
        this.bucketsSize = bucketsSize;
        this.bucketsSizeSet = true;
        return this;
    }


        @Override
        public OFBsnGentableSetBucketsSize build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                GenTableId tableId = this.tableIdSet ? this.tableId : parentMessage.tableId;
                if(tableId == null)
                    throw new NullPointerException("Property tableId must not be null");
                long bucketsSize = this.bucketsSizeSet ? this.bucketsSize : parentMessage.bucketsSize;

                //
                return new OFBsnGentableSetBucketsSizeVer13(
                    xid,
                    tableId,
                    bucketsSize
                );
        }

    }

    static class Builder implements OFBsnGentableSetBucketsSize.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean tableIdSet;
        private GenTableId tableId;
        private boolean bucketsSizeSet;
        private long bucketsSize;

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
    public OFBsnGentableSetBucketsSize.Builder setXid(long xid) {
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
        return 0x32L;
    }

    @Override
    public GenTableId getTableId() {
        return tableId;
    }

    @Override
    public OFBsnGentableSetBucketsSize.Builder setTableId(GenTableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public long getBucketsSize() {
        return bucketsSize;
    }

    @Override
    public OFBsnGentableSetBucketsSize.Builder setBucketsSize(long bucketsSize) {
        this.bucketsSize = bucketsSize;
        this.bucketsSizeSet = true;
        return this;
    }
//
        @Override
        public OFBsnGentableSetBucketsSize build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            if(!this.tableIdSet)
                throw new IllegalStateException("Property tableId doesn't have default value -- must be set");
            if(tableId == null)
                throw new NullPointerException("Property tableId must not be null");
            long bucketsSize = this.bucketsSizeSet ? this.bucketsSize : DEFAULT_BUCKETS_SIZE;


            return new OFBsnGentableSetBucketsSizeVer13(
                    xid,
                    tableId,
                    bucketsSize
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnGentableSetBucketsSize> {
        @Override
        public OFBsnGentableSetBucketsSize readFrom(ByteBuf bb) throws OFParseError {
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
            // fixed value property subtype == 0x32L
            int subtype = bb.readInt();
            if(subtype != 0x32)
                throw new OFParseError("Wrong subtype: Expected=0x32L(0x32L), got="+subtype);
            GenTableId tableId = GenTableId.read2Bytes(bb);
            // pad: 2 bytes
            bb.skipBytes(2);
            long bucketsSize = U32.f(bb.readInt());

            OFBsnGentableSetBucketsSizeVer13 bsnGentableSetBucketsSizeVer13 = new OFBsnGentableSetBucketsSizeVer13(
                    xid,
                      tableId,
                      bucketsSize
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnGentableSetBucketsSizeVer13);
            return bsnGentableSetBucketsSizeVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnGentableSetBucketsSizeVer13Funnel FUNNEL = new OFBsnGentableSetBucketsSizeVer13Funnel();
    static class OFBsnGentableSetBucketsSizeVer13Funnel implements Funnel<OFBsnGentableSetBucketsSizeVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnGentableSetBucketsSizeVer13 message, PrimitiveSink sink) {
            // fixed value property version = 4
            sink.putByte((byte) 0x4);
            // fixed value property type = 4
            sink.putByte((byte) 0x4);
            // fixed value property length = 24
            sink.putShort((short) 0x18);
            sink.putLong(message.xid);
            // fixed value property experimenter = 0x5c16c7L
            sink.putInt(0x5c16c7);
            // fixed value property subtype = 0x32L
            sink.putInt(0x32);
            message.tableId.putTo(sink);
            // skip pad (2 bytes)
            sink.putLong(message.bucketsSize);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnGentableSetBucketsSizeVer13> {
        @Override
        public void write(ByteBuf bb, OFBsnGentableSetBucketsSizeVer13 message) {
            // fixed value property version = 4
            bb.writeByte((byte) 0x4);
            // fixed value property type = 4
            bb.writeByte((byte) 0x4);
            // fixed value property length = 24
            bb.writeShort((short) 0x18);
            bb.writeInt(U32.t(message.xid));
            // fixed value property experimenter = 0x5c16c7L
            bb.writeInt(0x5c16c7);
            // fixed value property subtype = 0x32L
            bb.writeInt(0x32);
            message.tableId.write2Bytes(bb);
            // pad: 2 bytes
            bb.writeZero(2);
            bb.writeInt(U32.t(message.bucketsSize));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnGentableSetBucketsSizeVer13(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("tableId=").append(tableId);
        b.append(", ");
        b.append("bucketsSize=").append(bucketsSize);
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
        OFBsnGentableSetBucketsSizeVer13 other = (OFBsnGentableSetBucketsSizeVer13) obj;

        if( xid != other.xid)
            return false;
        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if( bucketsSize != other.bucketsSize)
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
        OFBsnGentableSetBucketsSizeVer13 other = (OFBsnGentableSetBucketsSizeVer13) obj;

        // ignore XID
        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if( bucketsSize != other.bucketsSize)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime *  (int) (bucketsSize ^ (bucketsSize >>> 32));
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime *  (int) (bucketsSize ^ (bucketsSize >>> 32));
        return result;
    }

}
