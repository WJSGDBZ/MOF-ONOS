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

class OFInstructionGotoTableVer14 implements OFInstructionGotoTable {
    private static final Logger logger = LoggerFactory.getLogger(OFInstructionGotoTableVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 8;

        private final static TableId DEFAULT_TABLE_ID = TableId.ALL;

    // OF message fields
    private final TableId tableId;
//
    // Immutable default instance
    final static OFInstructionGotoTableVer14 DEFAULT = new OFInstructionGotoTableVer14(
        DEFAULT_TABLE_ID
    );

    // package private constructor - used by readers, builders, and factory
    OFInstructionGotoTableVer14(TableId tableId) {
        if(tableId == null) {
            throw new NullPointerException("OFInstructionGotoTableVer14: property tableId cannot be null");
        }
        this.tableId = tableId;
    }

    // Accessors for OF message fields
    @Override
    public OFInstructionType getType() {
        return OFInstructionType.GOTO_TABLE;
    }

    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFInstructionGotoTable.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFInstructionGotoTable.Builder {
        final OFInstructionGotoTableVer14 parentMessage;

        // OF message fields
        private boolean tableIdSet;
        private TableId tableId;

        BuilderWithParent(OFInstructionGotoTableVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFInstructionType getType() {
        return OFInstructionType.GOTO_TABLE;
    }

    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFInstructionGotoTable.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFInstructionGotoTable build() {
                TableId tableId = this.tableIdSet ? this.tableId : parentMessage.tableId;
                if(tableId == null)
                    throw new NullPointerException("Property tableId must not be null");

                //
                return new OFInstructionGotoTableVer14(
                    tableId
                );
        }

    }

    static class Builder implements OFInstructionGotoTable.Builder {
        // OF message fields
        private boolean tableIdSet;
        private TableId tableId;

    @Override
    public OFInstructionType getType() {
        return OFInstructionType.GOTO_TABLE;
    }

    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFInstructionGotoTable.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFInstructionGotoTable build() {
            TableId tableId = this.tableIdSet ? this.tableId : DEFAULT_TABLE_ID;
            if(tableId == null)
                throw new NullPointerException("Property tableId must not be null");


            return new OFInstructionGotoTableVer14(
                    tableId
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFInstructionGotoTable> {
        @Override
        public OFInstructionGotoTable readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 1
            short type = bb.readShort();
            if(type != (short) 0x1)
                throw new OFParseError("Wrong type: Expected=OFInstructionType.GOTO_TABLE(1), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 8)
                throw new OFParseError("Wrong length: Expected=8(8), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            TableId tableId = TableId.readByte(bb);
            // pad: 3 bytes
            bb.skipBytes(3);

            OFInstructionGotoTableVer14 instructionGotoTableVer14 = new OFInstructionGotoTableVer14(
                    tableId
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", instructionGotoTableVer14);
            return instructionGotoTableVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFInstructionGotoTableVer14Funnel FUNNEL = new OFInstructionGotoTableVer14Funnel();
    static class OFInstructionGotoTableVer14Funnel implements Funnel<OFInstructionGotoTableVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFInstructionGotoTableVer14 message, PrimitiveSink sink) {
            // fixed value property type = 1
            sink.putShort((short) 0x1);
            // fixed value property length = 8
            sink.putShort((short) 0x8);
            message.tableId.putTo(sink);
            // skip pad (3 bytes)
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFInstructionGotoTableVer14> {
        @Override
        public void write(ByteBuf bb, OFInstructionGotoTableVer14 message) {
            // fixed value property type = 1
            bb.writeShort((short) 0x1);
            // fixed value property length = 8
            bb.writeShort((short) 0x8);
            message.tableId.writeByte(bb);
            // pad: 3 bytes
            bb.writeZero(3);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFInstructionGotoTableVer14(");
        b.append("tableId=").append(tableId);
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
        OFInstructionGotoTableVer14 other = (OFInstructionGotoTableVer14) obj;

        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        return result;
    }

}
