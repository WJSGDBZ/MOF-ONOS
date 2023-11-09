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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.List;
import java.util.Set;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFTableModVer11 implements OFTableMod {
    private static final Logger logger = LoggerFactory.getLogger(OFTableModVer11.class);
    // version: 1.1
    final static byte WIRE_VERSION = 2;
    final static int LENGTH = 16;

        private final static long DEFAULT_XID = 0x0L;
        private final static TableId DEFAULT_TABLE_ID = TableId.ALL;
        private final static long DEFAULT_CONFIG = 0x0L;

    // OF message fields
    private final long xid;
    private final TableId tableId;
    private final long config;
//
    // Immutable default instance
    final static OFTableModVer11 DEFAULT = new OFTableModVer11(
        DEFAULT_XID, DEFAULT_TABLE_ID, DEFAULT_CONFIG
    );

    // package private constructor - used by readers, builders, and factory
    OFTableModVer11(long xid, TableId tableId, long config) {
        if(tableId == null) {
            throw new NullPointerException("OFTableModVer11: property tableId cannot be null");
        }
        this.xid = U32.normalize(xid);
        this.tableId = tableId;
        this.config = U32.normalize(config);
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }

    @Override
    public OFType getType() {
        return OFType.TABLE_MOD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public long getConfig() {
        return config;
    }

    @Override
    public List<OFTableModProp> getProperties()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property properties not supported in version 1.1");
    }



    public OFTableMod.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFTableMod.Builder {
        final OFTableModVer11 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean tableIdSet;
        private TableId tableId;
        private boolean configSet;
        private long config;

        BuilderWithParent(OFTableModVer11 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }

    @Override
    public OFType getType() {
        return OFType.TABLE_MOD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFTableMod.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFTableMod.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public long getConfig() {
        return config;
    }

    @Override
    public OFTableMod.Builder setConfig(long config) {
        this.config = config;
        this.configSet = true;
        return this;
    }
    @Override
    public List<OFTableModProp> getProperties()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property properties not supported in version 1.1");
    }

    @Override
    public OFTableMod.Builder setProperties(List<OFTableModProp> properties) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property properties not supported in version 1.1");
    }


        @Override
        public OFTableMod build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                TableId tableId = this.tableIdSet ? this.tableId : parentMessage.tableId;
                if(tableId == null)
                    throw new NullPointerException("Property tableId must not be null");
                long config = this.configSet ? this.config : parentMessage.config;

                //
                return new OFTableModVer11(
                    xid,
                    tableId,
                    config
                );
        }

    }

    static class Builder implements OFTableMod.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean tableIdSet;
        private TableId tableId;
        private boolean configSet;
        private long config;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }

    @Override
    public OFType getType() {
        return OFType.TABLE_MOD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFTableMod.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFTableMod.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public long getConfig() {
        return config;
    }

    @Override
    public OFTableMod.Builder setConfig(long config) {
        this.config = config;
        this.configSet = true;
        return this;
    }
    @Override
    public List<OFTableModProp> getProperties()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property properties not supported in version 1.1");
    }

    @Override
    public OFTableMod.Builder setProperties(List<OFTableModProp> properties) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property properties not supported in version 1.1");
    }
//
        @Override
        public OFTableMod build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            TableId tableId = this.tableIdSet ? this.tableId : DEFAULT_TABLE_ID;
            if(tableId == null)
                throw new NullPointerException("Property tableId must not be null");
            long config = this.configSet ? this.config : DEFAULT_CONFIG;


            return new OFTableModVer11(
                    xid,
                    tableId,
                    config
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFTableMod> {
        @Override
        public OFTableMod readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 2
            byte version = bb.readByte();
            if(version != (byte) 0x2)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_11(2), got="+version);
            // fixed value property type == 17
            byte type = bb.readByte();
            if(type != (byte) 0x11)
                throw new OFParseError("Wrong type: Expected=OFType.TABLE_MOD(17), got="+type);
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
            TableId tableId = TableId.readByte(bb);
            // pad: 3 bytes
            bb.skipBytes(3);
            long config = U32.f(bb.readInt());

            OFTableModVer11 tableModVer11 = new OFTableModVer11(
                    xid,
                      tableId,
                      config
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", tableModVer11);
            return tableModVer11;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFTableModVer11Funnel FUNNEL = new OFTableModVer11Funnel();
    static class OFTableModVer11Funnel implements Funnel<OFTableModVer11> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFTableModVer11 message, PrimitiveSink sink) {
            // fixed value property version = 2
            sink.putByte((byte) 0x2);
            // fixed value property type = 17
            sink.putByte((byte) 0x11);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            sink.putLong(message.xid);
            message.tableId.putTo(sink);
            // skip pad (3 bytes)
            sink.putLong(message.config);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFTableModVer11> {
        @Override
        public void write(ByteBuf bb, OFTableModVer11 message) {
            // fixed value property version = 2
            bb.writeByte((byte) 0x2);
            // fixed value property type = 17
            bb.writeByte((byte) 0x11);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            bb.writeInt(U32.t(message.xid));
            message.tableId.writeByte(bb);
            // pad: 3 bytes
            bb.writeZero(3);
            bb.writeInt(U32.t(message.config));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFTableModVer11(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("tableId=").append(tableId);
        b.append(", ");
        b.append("config=").append(config);
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
        OFTableModVer11 other = (OFTableModVer11) obj;

        if( xid != other.xid)
            return false;
        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if( config != other.config)
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
        OFTableModVer11 other = (OFTableModVer11) obj;

        // ignore XID
        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if( config != other.config)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime *  (int) (config ^ (config >>> 32));
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime *  (int) (config ^ (config >>> 32));
        return result;
    }

}
