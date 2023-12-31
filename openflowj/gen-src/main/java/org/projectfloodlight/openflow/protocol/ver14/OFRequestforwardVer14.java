// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver14;

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

class OFRequestforwardVer14 implements OFRequestforward {
    private static final Logger logger = LoggerFactory.getLogger(OFRequestforwardVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int MINIMUM_LENGTH = 12;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static long DEFAULT_XID = 0x0L;
        private final static long DEFAULT_ROLE = 0x0L;
        private final static byte[] DEFAULT_DATA = new byte[0];

    // OF message fields
    private final long xid;
    private final long role;
    private final byte[] data;
//
    // Immutable default instance
    final static OFRequestforwardVer14 DEFAULT = new OFRequestforwardVer14(
        DEFAULT_XID, DEFAULT_ROLE, DEFAULT_DATA
    );

    // package private constructor - used by readers, builders, and factory
    OFRequestforwardVer14(long xid, long role, byte[] data) {
        if(data == null) {
            throw new NullPointerException("OFRequestforwardVer14: property data cannot be null");
        }
        this.xid = U32.normalize(xid);
        this.role = U32.normalize(role);
        this.data = data;
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

    @Override
    public OFType getType() {
        return OFType.REQUESTFORWARD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public long getRole() {
        return role;
    }

    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public OFMessage getRequest()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property request not supported in version 1.4");
    }



    public OFRequestforward.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFRequestforward.Builder {
        final OFRequestforwardVer14 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean roleSet;
        private long role;
        private boolean dataSet;
        private byte[] data;

        BuilderWithParent(OFRequestforwardVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

    @Override
    public OFType getType() {
        return OFType.REQUESTFORWARD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFRequestforward.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public long getRole() {
        return role;
    }

    @Override
    public OFRequestforward.Builder setRole(long role) {
        this.role = role;
        this.roleSet = true;
        return this;
    }
    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public OFRequestforward.Builder setData(byte[] data) {
        this.data = data;
        this.dataSet = true;
        return this;
    }
    @Override
    public OFMessage getRequest()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property request not supported in version 1.4");
    }

    @Override
    public OFRequestforward.Builder setRequest(OFMessage request) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property request not supported in version 1.4");
    }


        @Override
        public OFRequestforward build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                long role = this.roleSet ? this.role : parentMessage.role;
                byte[] data = this.dataSet ? this.data : parentMessage.data;
                if(data == null)
                    throw new NullPointerException("Property data must not be null");

                //
                return new OFRequestforwardVer14(
                    xid,
                    role,
                    data
                );
        }

    }

    static class Builder implements OFRequestforward.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean roleSet;
        private long role;
        private boolean dataSet;
        private byte[] data;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

    @Override
    public OFType getType() {
        return OFType.REQUESTFORWARD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFRequestforward.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public long getRole() {
        return role;
    }

    @Override
    public OFRequestforward.Builder setRole(long role) {
        this.role = role;
        this.roleSet = true;
        return this;
    }
    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public OFRequestforward.Builder setData(byte[] data) {
        this.data = data;
        this.dataSet = true;
        return this;
    }
    @Override
    public OFMessage getRequest()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property request not supported in version 1.4");
    }

    @Override
    public OFRequestforward.Builder setRequest(OFMessage request) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property request not supported in version 1.4");
    }
//
        @Override
        public OFRequestforward build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            long role = this.roleSet ? this.role : DEFAULT_ROLE;
            byte[] data = this.dataSet ? this.data : DEFAULT_DATA;
            if(data == null)
                throw new NullPointerException("Property data must not be null");


            return new OFRequestforwardVer14(
                    xid,
                    role,
                    data
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFRequestforward> {
        @Override
        public OFRequestforward readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 5
            byte version = bb.readByte();
            if(version != (byte) 0x5)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_14(5), got="+version);
            // fixed value property type == 32
            byte type = bb.readByte();
            if(type != (byte) 0x20)
                throw new OFParseError("Wrong type: Expected=OFType.REQUESTFORWARD(32), got="+type);
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
            long role = U32.f(bb.readInt());
            byte[] data = ChannelUtils.readBytes(bb, length - (bb.readerIndex() - start));

            OFRequestforwardVer14 requestforwardVer14 = new OFRequestforwardVer14(
                    xid,
                      role,
                      data
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", requestforwardVer14);
            return requestforwardVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFRequestforwardVer14Funnel FUNNEL = new OFRequestforwardVer14Funnel();
    static class OFRequestforwardVer14Funnel implements Funnel<OFRequestforwardVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFRequestforwardVer14 message, PrimitiveSink sink) {
            // fixed value property version = 5
            sink.putByte((byte) 0x5);
            // fixed value property type = 32
            sink.putByte((byte) 0x20);
            // FIXME: skip funnel of length
            sink.putLong(message.xid);
            sink.putLong(message.role);
            sink.putBytes(message.data);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFRequestforwardVer14> {
        @Override
        public void write(ByteBuf bb, OFRequestforwardVer14 message) {
            int startIndex = bb.writerIndex();
            // fixed value property version = 5
            bb.writeByte((byte) 0x5);
            // fixed value property type = 32
            bb.writeByte((byte) 0x20);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            bb.writeInt(U32.t(message.xid));
            bb.writeInt(U32.t(message.role));
            bb.writeBytes(message.data);

            // update length field
            int length = bb.writerIndex() - startIndex;
            if (length > MAXIMUM_LENGTH) {
                throw new IllegalArgumentException("OFRequestforwardVer14: message length (" + length + ") exceeds maximum (0xFFFF)");
            }
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFRequestforwardVer14(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("role=").append(role);
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
        OFRequestforwardVer14 other = (OFRequestforwardVer14) obj;

        if( xid != other.xid)
            return false;
        if( role != other.role)
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
        OFRequestforwardVer14 other = (OFRequestforwardVer14) obj;

        // ignore XID
        if( role != other.role)
            return false;
        if (!Arrays.equals(data, other.data))
                return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime *  (int) (role ^ (role >>> 32));
        result = prime * result + Arrays.hashCode(data);
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime *  (int) (role ^ (role >>> 32));
        result = prime * result + Arrays.hashCode(data);
        return result;
    }

}
