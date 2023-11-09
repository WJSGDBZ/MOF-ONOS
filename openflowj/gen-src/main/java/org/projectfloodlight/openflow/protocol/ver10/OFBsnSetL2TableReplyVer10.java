// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver10;

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

class OFBsnSetL2TableReplyVer10 implements OFBsnSetL2TableReply {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnSetL2TableReplyVer10.class);
    // version: 1.0
    final static byte WIRE_VERSION = 1;
    final static int LENGTH = 24;

        private final static long DEFAULT_XID = 0x0L;
        private final static boolean DEFAULT_L2_TABLE_ENABLE = false;
        private final static int DEFAULT_L2_TABLE_PRIORITY = 0x0;
        private final static long DEFAULT_STATUS = 0x0L;

    // OF message fields
    private final long xid;
    private final boolean l2TableEnable;
    private final int l2TablePriority;
    private final long status;
//
    // Immutable default instance
    final static OFBsnSetL2TableReplyVer10 DEFAULT = new OFBsnSetL2TableReplyVer10(
        DEFAULT_XID, DEFAULT_L2_TABLE_ENABLE, DEFAULT_L2_TABLE_PRIORITY, DEFAULT_STATUS
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnSetL2TableReplyVer10(long xid, boolean l2TableEnable, int l2TablePriority, long status) {
        this.xid = U32.normalize(xid);
        this.l2TableEnable = l2TableEnable;
        this.l2TablePriority = U16.normalize(l2TablePriority);
        this.status = U32.normalize(status);
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
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
        return 0x18L;
    }

    @Override
    public boolean isL2TableEnable() {
        return l2TableEnable;
    }

    @Override
    public int getL2TablePriority() {
        return l2TablePriority;
    }

    @Override
    public long getStatus() {
        return status;
    }



    public OFBsnSetL2TableReply.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnSetL2TableReply.Builder {
        final OFBsnSetL2TableReplyVer10 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean l2TableEnableSet;
        private boolean l2TableEnable;
        private boolean l2TablePrioritySet;
        private int l2TablePriority;
        private boolean statusSet;
        private long status;

        BuilderWithParent(OFBsnSetL2TableReplyVer10 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
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
    public OFBsnSetL2TableReply.Builder setXid(long xid) {
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
        return 0x18L;
    }

    @Override
    public boolean isL2TableEnable() {
        return l2TableEnable;
    }

    @Override
    public OFBsnSetL2TableReply.Builder setL2TableEnable(boolean l2TableEnable) {
        this.l2TableEnable = l2TableEnable;
        this.l2TableEnableSet = true;
        return this;
    }
    @Override
    public int getL2TablePriority() {
        return l2TablePriority;
    }

    @Override
    public OFBsnSetL2TableReply.Builder setL2TablePriority(int l2TablePriority) {
        this.l2TablePriority = l2TablePriority;
        this.l2TablePrioritySet = true;
        return this;
    }
    @Override
    public long getStatus() {
        return status;
    }

    @Override
    public OFBsnSetL2TableReply.Builder setStatus(long status) {
        this.status = status;
        this.statusSet = true;
        return this;
    }


        @Override
        public OFBsnSetL2TableReply build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                boolean l2TableEnable = this.l2TableEnableSet ? this.l2TableEnable : parentMessage.l2TableEnable;
                int l2TablePriority = this.l2TablePrioritySet ? this.l2TablePriority : parentMessage.l2TablePriority;
                long status = this.statusSet ? this.status : parentMessage.status;

                //
                return new OFBsnSetL2TableReplyVer10(
                    xid,
                    l2TableEnable,
                    l2TablePriority,
                    status
                );
        }

    }

    static class Builder implements OFBsnSetL2TableReply.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean l2TableEnableSet;
        private boolean l2TableEnable;
        private boolean l2TablePrioritySet;
        private int l2TablePriority;
        private boolean statusSet;
        private long status;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
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
    public OFBsnSetL2TableReply.Builder setXid(long xid) {
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
        return 0x18L;
    }

    @Override
    public boolean isL2TableEnable() {
        return l2TableEnable;
    }

    @Override
    public OFBsnSetL2TableReply.Builder setL2TableEnable(boolean l2TableEnable) {
        this.l2TableEnable = l2TableEnable;
        this.l2TableEnableSet = true;
        return this;
    }
    @Override
    public int getL2TablePriority() {
        return l2TablePriority;
    }

    @Override
    public OFBsnSetL2TableReply.Builder setL2TablePriority(int l2TablePriority) {
        this.l2TablePriority = l2TablePriority;
        this.l2TablePrioritySet = true;
        return this;
    }
    @Override
    public long getStatus() {
        return status;
    }

    @Override
    public OFBsnSetL2TableReply.Builder setStatus(long status) {
        this.status = status;
        this.statusSet = true;
        return this;
    }
//
        @Override
        public OFBsnSetL2TableReply build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            boolean l2TableEnable = this.l2TableEnableSet ? this.l2TableEnable : DEFAULT_L2_TABLE_ENABLE;
            int l2TablePriority = this.l2TablePrioritySet ? this.l2TablePriority : DEFAULT_L2_TABLE_PRIORITY;
            long status = this.statusSet ? this.status : DEFAULT_STATUS;


            return new OFBsnSetL2TableReplyVer10(
                    xid,
                    l2TableEnable,
                    l2TablePriority,
                    status
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnSetL2TableReply> {
        @Override
        public OFBsnSetL2TableReply readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 1
            byte version = bb.readByte();
            if(version != (byte) 0x1)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_10(1), got="+version);
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
            // fixed value property subtype == 0x18L
            int subtype = bb.readInt();
            if(subtype != 0x18)
                throw new OFParseError("Wrong subtype: Expected=0x18L(0x18L), got="+subtype);
            boolean l2TableEnable = (bb.readByte() != 0);
            // pad: 1 bytes
            bb.skipBytes(1);
            int l2TablePriority = U16.f(bb.readShort());
            long status = U32.f(bb.readInt());

            OFBsnSetL2TableReplyVer10 bsnSetL2TableReplyVer10 = new OFBsnSetL2TableReplyVer10(
                    xid,
                      l2TableEnable,
                      l2TablePriority,
                      status
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnSetL2TableReplyVer10);
            return bsnSetL2TableReplyVer10;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnSetL2TableReplyVer10Funnel FUNNEL = new OFBsnSetL2TableReplyVer10Funnel();
    static class OFBsnSetL2TableReplyVer10Funnel implements Funnel<OFBsnSetL2TableReplyVer10> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnSetL2TableReplyVer10 message, PrimitiveSink sink) {
            // fixed value property version = 1
            sink.putByte((byte) 0x1);
            // fixed value property type = 4
            sink.putByte((byte) 0x4);
            // fixed value property length = 24
            sink.putShort((short) 0x18);
            sink.putLong(message.xid);
            // fixed value property experimenter = 0x5c16c7L
            sink.putInt(0x5c16c7);
            // fixed value property subtype = 0x18L
            sink.putInt(0x18);
            sink.putBoolean(message.l2TableEnable);
            // skip pad (1 bytes)
            sink.putInt(message.l2TablePriority);
            sink.putLong(message.status);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnSetL2TableReplyVer10> {
        @Override
        public void write(ByteBuf bb, OFBsnSetL2TableReplyVer10 message) {
            // fixed value property version = 1
            bb.writeByte((byte) 0x1);
            // fixed value property type = 4
            bb.writeByte((byte) 0x4);
            // fixed value property length = 24
            bb.writeShort((short) 0x18);
            bb.writeInt(U32.t(message.xid));
            // fixed value property experimenter = 0x5c16c7L
            bb.writeInt(0x5c16c7);
            // fixed value property subtype = 0x18L
            bb.writeInt(0x18);
            bb.writeByte(message.l2TableEnable ? 1 : 0);
            // pad: 1 bytes
            bb.writeZero(1);
            bb.writeShort(U16.t(message.l2TablePriority));
            bb.writeInt(U32.t(message.status));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnSetL2TableReplyVer10(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("l2TableEnable=").append(l2TableEnable);
        b.append(", ");
        b.append("l2TablePriority=").append(l2TablePriority);
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
        OFBsnSetL2TableReplyVer10 other = (OFBsnSetL2TableReplyVer10) obj;

        if( xid != other.xid)
            return false;
        if( l2TableEnable != other.l2TableEnable)
            return false;
        if( l2TablePriority != other.l2TablePriority)
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
        OFBsnSetL2TableReplyVer10 other = (OFBsnSetL2TableReplyVer10) obj;

        // ignore XID
        if( l2TableEnable != other.l2TableEnable)
            return false;
        if( l2TablePriority != other.l2TablePriority)
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
        result = prime * result + (l2TableEnable ? 1231 : 1237);
        result = prime * result + l2TablePriority;
        result = prime *  (int) (status ^ (status >>> 32));
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + (l2TableEnable ? 1231 : 1237);
        result = prime * result + l2TablePriority;
        result = prime *  (int) (status ^ (status >>> 32));
        return result;
    }

}
