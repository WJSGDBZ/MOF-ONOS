// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver12;

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

class OFRoleRequestVer12 implements OFRoleRequest {
    private static final Logger logger = LoggerFactory.getLogger(OFRoleRequestVer12.class);
    // version: 1.2
    final static byte WIRE_VERSION = 3;
    final static int LENGTH = 24;

        private final static long DEFAULT_XID = 0x0L;
        private final static U64 DEFAULT_GENERATION_ID = U64.ZERO;

    // OF message fields
    private final long xid;
    private final OFControllerRole role;
    private final U64 generationId;
//

    // package private constructor - used by readers, builders, and factory
    OFRoleRequestVer12(long xid, OFControllerRole role, U64 generationId) {
        if(role == null) {
            throw new NullPointerException("OFRoleRequestVer12: property role cannot be null");
        }
        if(generationId == null) {
            throw new NullPointerException("OFRoleRequestVer12: property generationId cannot be null");
        }
        this.xid = U32.normalize(xid);
        this.role = role;
        this.generationId = generationId;
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }

    @Override
    public OFType getType() {
        return OFType.ROLE_REQUEST;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFControllerRole getRole() {
        return role;
    }

    @Override
    public U64 getGenerationId() {
        return generationId;
    }

    @Override
    public int getShortId()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property shortId not supported in version 1.2");
    }



    public OFRoleRequest.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFRoleRequest.Builder {
        final OFRoleRequestVer12 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean roleSet;
        private OFControllerRole role;
        private boolean generationIdSet;
        private U64 generationId;

        BuilderWithParent(OFRoleRequestVer12 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }

    @Override
    public OFType getType() {
        return OFType.ROLE_REQUEST;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFRoleRequest.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public OFControllerRole getRole() {
        return role;
    }

    @Override
    public OFRoleRequest.Builder setRole(OFControllerRole role) {
        this.role = role;
        this.roleSet = true;
        return this;
    }
    @Override
    public U64 getGenerationId() {
        return generationId;
    }

    @Override
    public OFRoleRequest.Builder setGenerationId(U64 generationId) {
        this.generationId = generationId;
        this.generationIdSet = true;
        return this;
    }
    @Override
    public int getShortId()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property shortId not supported in version 1.2");
    }

    @Override
    public OFRoleRequest.Builder setShortId(int shortId) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property shortId not supported in version 1.2");
    }


        @Override
        public OFRoleRequest build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                OFControllerRole role = this.roleSet ? this.role : parentMessage.role;
                if(role == null)
                    throw new NullPointerException("Property role must not be null");
                U64 generationId = this.generationIdSet ? this.generationId : parentMessage.generationId;
                if(generationId == null)
                    throw new NullPointerException("Property generationId must not be null");

                //
                return new OFRoleRequestVer12(
                    xid,
                    role,
                    generationId
                );
        }

    }

    static class Builder implements OFRoleRequest.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean roleSet;
        private OFControllerRole role;
        private boolean generationIdSet;
        private U64 generationId;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }

    @Override
    public OFType getType() {
        return OFType.ROLE_REQUEST;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFRoleRequest.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public OFControllerRole getRole() {
        return role;
    }

    @Override
    public OFRoleRequest.Builder setRole(OFControllerRole role) {
        this.role = role;
        this.roleSet = true;
        return this;
    }
    @Override
    public U64 getGenerationId() {
        return generationId;
    }

    @Override
    public OFRoleRequest.Builder setGenerationId(U64 generationId) {
        this.generationId = generationId;
        this.generationIdSet = true;
        return this;
    }
    @Override
    public int getShortId()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property shortId not supported in version 1.2");
    }

    @Override
    public OFRoleRequest.Builder setShortId(int shortId) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property shortId not supported in version 1.2");
    }
//
        @Override
        public OFRoleRequest build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            if(!this.roleSet)
                throw new IllegalStateException("Property role doesn't have default value -- must be set");
            if(role == null)
                throw new NullPointerException("Property role must not be null");
            U64 generationId = this.generationIdSet ? this.generationId : DEFAULT_GENERATION_ID;
            if(generationId == null)
                throw new NullPointerException("Property generationId must not be null");


            return new OFRoleRequestVer12(
                    xid,
                    role,
                    generationId
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFRoleRequest> {
        @Override
        public OFRoleRequest readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 3
            byte version = bb.readByte();
            if(version != (byte) 0x3)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_12(3), got="+version);
            // fixed value property type == 24
            byte type = bb.readByte();
            if(type != (byte) 0x18)
                throw new OFParseError("Wrong type: Expected=OFType.ROLE_REQUEST(24), got="+type);
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
            OFControllerRole role = OFControllerRoleSerializerVer12.readFrom(bb);
            // pad: 4 bytes
            bb.skipBytes(4);
            U64 generationId = U64.ofRaw(bb.readLong());

            OFRoleRequestVer12 roleRequestVer12 = new OFRoleRequestVer12(
                    xid,
                      role,
                      generationId
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", roleRequestVer12);
            return roleRequestVer12;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFRoleRequestVer12Funnel FUNNEL = new OFRoleRequestVer12Funnel();
    static class OFRoleRequestVer12Funnel implements Funnel<OFRoleRequestVer12> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFRoleRequestVer12 message, PrimitiveSink sink) {
            // fixed value property version = 3
            sink.putByte((byte) 0x3);
            // fixed value property type = 24
            sink.putByte((byte) 0x18);
            // fixed value property length = 24
            sink.putShort((short) 0x18);
            sink.putLong(message.xid);
            OFControllerRoleSerializerVer12.putTo(message.role, sink);
            // skip pad (4 bytes)
            message.generationId.putTo(sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFRoleRequestVer12> {
        @Override
        public void write(ByteBuf bb, OFRoleRequestVer12 message) {
            // fixed value property version = 3
            bb.writeByte((byte) 0x3);
            // fixed value property type = 24
            bb.writeByte((byte) 0x18);
            // fixed value property length = 24
            bb.writeShort((short) 0x18);
            bb.writeInt(U32.t(message.xid));
            OFControllerRoleSerializerVer12.writeTo(bb, message.role);
            // pad: 4 bytes
            bb.writeZero(4);
            bb.writeLong(message.generationId.getValue());


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFRoleRequestVer12(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("role=").append(role);
        b.append(", ");
        b.append("generationId=").append(generationId);
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
        OFRoleRequestVer12 other = (OFRoleRequestVer12) obj;

        if( xid != other.xid)
            return false;
        if (role == null) {
            if (other.role != null)
                return false;
        } else if (!role.equals(other.role))
            return false;
        if (generationId == null) {
            if (other.generationId != null)
                return false;
        } else if (!generationId.equals(other.generationId))
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
        OFRoleRequestVer12 other = (OFRoleRequestVer12) obj;

        // ignore XID
        if (role == null) {
            if (other.role != null)
                return false;
        } else if (!role.equals(other.role))
            return false;
        if (generationId == null) {
            if (other.generationId != null)
                return false;
        } else if (!generationId.equals(other.generationId))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime * result + ((role == null) ? 0 : role.hashCode());
        result = prime * result + ((generationId == null) ? 0 : generationId.hashCode());
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + ((role == null) ? 0 : role.hashCode());
        result = prime * result + ((generationId == null) ? 0 : generationId.hashCode());
        return result;
    }

}
