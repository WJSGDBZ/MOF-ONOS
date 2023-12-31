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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Set;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;
import java.util.Arrays;

class OFEchoReplyVer10 implements OFEchoReply {
    private static final Logger logger = LoggerFactory.getLogger(OFEchoReplyVer10.class);
    // version: 1.0
    final static byte WIRE_VERSION = 1;
    final static int MINIMUM_LENGTH = 8;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static long DEFAULT_XID = 0x0L;
        private final static byte[] DEFAULT_DATA = new byte[0];

    // OF message fields
    private final long xid;
    private final byte[] data;
//
    // Immutable default instance
    final static OFEchoReplyVer10 DEFAULT = new OFEchoReplyVer10(
        DEFAULT_XID, DEFAULT_DATA
    );

    // package private constructor - used by readers, builders, and factory
    OFEchoReplyVer10(long xid, byte[] data) {
        if(data == null) {
            throw new NullPointerException("OFEchoReplyVer10: property data cannot be null");
        }
        this.xid = U32.normalize(xid);
        this.data = data;
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
    }

    @Override
    public OFType getType() {
        return OFType.ECHO_REPLY;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public byte[] getData() {
        return data;
    }



    public OFEchoReply.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFEchoReply.Builder {
        final OFEchoReplyVer10 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean dataSet;
        private byte[] data;

        BuilderWithParent(OFEchoReplyVer10 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
    }

    @Override
    public OFType getType() {
        return OFType.ECHO_REPLY;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFEchoReply.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public OFEchoReply.Builder setData(byte[] data) {
        this.data = data;
        this.dataSet = true;
        return this;
    }


        @Override
        public OFEchoReply build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                byte[] data = this.dataSet ? this.data : parentMessage.data;
                if(data == null)
                    throw new NullPointerException("Property data must not be null");

                //
                return new OFEchoReplyVer10(
                    xid,
                    data
                );
        }

    }

    static class Builder implements OFEchoReply.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean dataSet;
        private byte[] data;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
    }

    @Override
    public OFType getType() {
        return OFType.ECHO_REPLY;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFEchoReply.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public OFEchoReply.Builder setData(byte[] data) {
        this.data = data;
        this.dataSet = true;
        return this;
    }
//
        @Override
        public OFEchoReply build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            byte[] data = this.dataSet ? this.data : DEFAULT_DATA;
            if(data == null)
                throw new NullPointerException("Property data must not be null");


            return new OFEchoReplyVer10(
                    xid,
                    data
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFEchoReply> {
        @Override
        public OFEchoReply readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 1
            byte version = bb.readByte();
            if(version != (byte) 0x1)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_10(1), got="+version);
            // fixed value property type == 3
            byte type = bb.readByte();
            if(type != (byte) 0x3)
                throw new OFParseError("Wrong type: Expected=OFType.ECHO_REPLY(3), got="+type);
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
            long xid = U32.f(bb.readInt());
            byte[] data = ChannelUtils.readBytes(bb, length - (bb.readerIndex() - start));

            OFEchoReplyVer10 echoReplyVer10 = new OFEchoReplyVer10(
                    xid,
                      data
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", echoReplyVer10);
            return echoReplyVer10;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFEchoReplyVer10Funnel FUNNEL = new OFEchoReplyVer10Funnel();
    static class OFEchoReplyVer10Funnel implements Funnel<OFEchoReplyVer10> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFEchoReplyVer10 message, PrimitiveSink sink) {
            // fixed value property version = 1
            sink.putByte((byte) 0x1);
            // fixed value property type = 3
            sink.putByte((byte) 0x3);
            // FIXME: skip funnel of length
            sink.putLong(message.xid);
            sink.putBytes(message.data);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFEchoReplyVer10> {
        @Override
        public void write(ByteBuf bb, OFEchoReplyVer10 message) {
            int startIndex = bb.writerIndex();
            // fixed value property version = 1
            bb.writeByte((byte) 0x1);
            // fixed value property type = 3
            bb.writeByte((byte) 0x3);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            bb.writeInt(U32.t(message.xid));
            bb.writeBytes(message.data);

            // update length field
            int length = bb.writerIndex() - startIndex;
            if (length > MAXIMUM_LENGTH) {
                throw new IllegalArgumentException("OFEchoReplyVer10: message length (" + length + ") exceeds maximum (0xFFFF)");
            }
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFEchoReplyVer10(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("data=").append(Arrays.toString(data));
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
        OFEchoReplyVer10 other = (OFEchoReplyVer10) obj;

        if( xid != other.xid)
            return false;
        if (!Arrays.equals(data, other.data))
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
        OFEchoReplyVer10 other = (OFEchoReplyVer10) obj;

        // ignore XID
        if (!Arrays.equals(data, other.data))
                return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime * result + Arrays.hashCode(data);
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + Arrays.hashCode(data);
        return result;
    }

}
