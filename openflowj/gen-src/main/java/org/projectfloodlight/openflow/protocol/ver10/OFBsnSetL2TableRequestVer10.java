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

class OFBsnSetL2TableRequestVer10 implements OFBsnSetL2TableRequest {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnSetL2TableRequestVer10.class);
    // version: 1.0
    final static byte WIRE_VERSION = 1;
    final static int LENGTH = 24;

        private final static long DEFAULT_XID = 0x0L;
        private final static boolean DEFAULT_L2_TABLE_ENABLE = false;
        private final static int DEFAULT_L2_TABLE_PRIORITY = 0x0;

    // OF message fields
    private final long xid;
    private final boolean l2TableEnable;
    private final int l2TablePriority;
//
    // Immutable default instance
    final static OFBsnSetL2TableRequestVer10 DEFAULT = new OFBsnSetL2TableRequestVer10(
        DEFAULT_XID, DEFAULT_L2_TABLE_ENABLE, DEFAULT_L2_TABLE_PRIORITY
    );

    // package private constructor - used by readers, builders, and factory
    OFBsnSetL2TableRequestVer10(long xid, boolean l2TableEnable, int l2TablePriority) {
        this.xid = U32.normalize(xid);
        this.l2TableEnable = l2TableEnable;
        this.l2TablePriority = U16.normalize(l2TablePriority);
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
        return 0xcL;
    }

    @Override
    public boolean isL2TableEnable() {
        return l2TableEnable;
    }

    @Override
    public int getL2TablePriority() {
        return l2TablePriority;
    }



    public OFBsnSetL2TableRequest.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnSetL2TableRequest.Builder {
        final OFBsnSetL2TableRequestVer10 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean l2TableEnableSet;
        private boolean l2TableEnable;
        private boolean l2TablePrioritySet;
        private int l2TablePriority;

        BuilderWithParent(OFBsnSetL2TableRequestVer10 parentMessage) {
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
    public OFBsnSetL2TableRequest.Builder setXid(long xid) {
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
        return 0xcL;
    }

    @Override
    public boolean isL2TableEnable() {
        return l2TableEnable;
    }

    @Override
    public OFBsnSetL2TableRequest.Builder setL2TableEnable(boolean l2TableEnable) {
        this.l2TableEnable = l2TableEnable;
        this.l2TableEnableSet = true;
        return this;
    }
    @Override
    public int getL2TablePriority() {
        return l2TablePriority;
    }

    @Override
    public OFBsnSetL2TableRequest.Builder setL2TablePriority(int l2TablePriority) {
        this.l2TablePriority = l2TablePriority;
        this.l2TablePrioritySet = true;
        return this;
    }


        @Override
        public OFBsnSetL2TableRequest build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                boolean l2TableEnable = this.l2TableEnableSet ? this.l2TableEnable : parentMessage.l2TableEnable;
                int l2TablePriority = this.l2TablePrioritySet ? this.l2TablePriority : parentMessage.l2TablePriority;

                //
                return new OFBsnSetL2TableRequestVer10(
                    xid,
                    l2TableEnable,
                    l2TablePriority
                );
        }

    }

    static class Builder implements OFBsnSetL2TableRequest.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean l2TableEnableSet;
        private boolean l2TableEnable;
        private boolean l2TablePrioritySet;
        private int l2TablePriority;

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
    public OFBsnSetL2TableRequest.Builder setXid(long xid) {
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
        return 0xcL;
    }

    @Override
    public boolean isL2TableEnable() {
        return l2TableEnable;
    }

    @Override
    public OFBsnSetL2TableRequest.Builder setL2TableEnable(boolean l2TableEnable) {
        this.l2TableEnable = l2TableEnable;
        this.l2TableEnableSet = true;
        return this;
    }
    @Override
    public int getL2TablePriority() {
        return l2TablePriority;
    }

    @Override
    public OFBsnSetL2TableRequest.Builder setL2TablePriority(int l2TablePriority) {
        this.l2TablePriority = l2TablePriority;
        this.l2TablePrioritySet = true;
        return this;
    }
//
        @Override
        public OFBsnSetL2TableRequest build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            boolean l2TableEnable = this.l2TableEnableSet ? this.l2TableEnable : DEFAULT_L2_TABLE_ENABLE;
            int l2TablePriority = this.l2TablePrioritySet ? this.l2TablePriority : DEFAULT_L2_TABLE_PRIORITY;


            return new OFBsnSetL2TableRequestVer10(
                    xid,
                    l2TableEnable,
                    l2TablePriority
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnSetL2TableRequest> {
        @Override
        public OFBsnSetL2TableRequest readFrom(ByteBuf bb) throws OFParseError {
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
            // fixed value property subtype == 0xcL
            int subtype = bb.readInt();
            if(subtype != 0xc)
                throw new OFParseError("Wrong subtype: Expected=0xcL(0xcL), got="+subtype);
            boolean l2TableEnable = (bb.readByte() != 0);
            // pad: 1 bytes
            bb.skipBytes(1);
            int l2TablePriority = U16.f(bb.readShort());
            // pad: 4 bytes
            bb.skipBytes(4);

            OFBsnSetL2TableRequestVer10 bsnSetL2TableRequestVer10 = new OFBsnSetL2TableRequestVer10(
                    xid,
                      l2TableEnable,
                      l2TablePriority
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnSetL2TableRequestVer10);
            return bsnSetL2TableRequestVer10;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnSetL2TableRequestVer10Funnel FUNNEL = new OFBsnSetL2TableRequestVer10Funnel();
    static class OFBsnSetL2TableRequestVer10Funnel implements Funnel<OFBsnSetL2TableRequestVer10> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnSetL2TableRequestVer10 message, PrimitiveSink sink) {
            // fixed value property version = 1
            sink.putByte((byte) 0x1);
            // fixed value property type = 4
            sink.putByte((byte) 0x4);
            // fixed value property length = 24
            sink.putShort((short) 0x18);
            sink.putLong(message.xid);
            // fixed value property experimenter = 0x5c16c7L
            sink.putInt(0x5c16c7);
            // fixed value property subtype = 0xcL
            sink.putInt(0xc);
            sink.putBoolean(message.l2TableEnable);
            // skip pad (1 bytes)
            sink.putInt(message.l2TablePriority);
            // skip pad (4 bytes)
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnSetL2TableRequestVer10> {
        @Override
        public void write(ByteBuf bb, OFBsnSetL2TableRequestVer10 message) {
            // fixed value property version = 1
            bb.writeByte((byte) 0x1);
            // fixed value property type = 4
            bb.writeByte((byte) 0x4);
            // fixed value property length = 24
            bb.writeShort((short) 0x18);
            bb.writeInt(U32.t(message.xid));
            // fixed value property experimenter = 0x5c16c7L
            bb.writeInt(0x5c16c7);
            // fixed value property subtype = 0xcL
            bb.writeInt(0xc);
            bb.writeByte(message.l2TableEnable ? 1 : 0);
            // pad: 1 bytes
            bb.writeZero(1);
            bb.writeShort(U16.t(message.l2TablePriority));
            // pad: 4 bytes
            bb.writeZero(4);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnSetL2TableRequestVer10(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("l2TableEnable=").append(l2TableEnable);
        b.append(", ");
        b.append("l2TablePriority=").append(l2TablePriority);
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
        OFBsnSetL2TableRequestVer10 other = (OFBsnSetL2TableRequestVer10) obj;

        if( xid != other.xid)
            return false;
        if( l2TableEnable != other.l2TableEnable)
            return false;
        if( l2TablePriority != other.l2TablePriority)
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
        OFBsnSetL2TableRequestVer10 other = (OFBsnSetL2TableRequestVer10) obj;

        // ignore XID
        if( l2TableEnable != other.l2TableEnable)
            return false;
        if( l2TablePriority != other.l2TablePriority)
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
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + (l2TableEnable ? 1231 : 1237);
        result = prime * result + l2TablePriority;
        return result;
    }

}
