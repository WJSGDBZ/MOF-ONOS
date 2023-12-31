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
import com.google.common.collect.ImmutableSet;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFFlowMonitorEntryVer15 implements OFFlowMonitorEntry {
    private static final Logger logger = LoggerFactory.getLogger(OFFlowMonitorEntryVer15.class);
    // version: 1.5
    final static byte WIRE_VERSION = 6;
    final static int MINIMUM_LENGTH = 24;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static long DEFAULT_MONITOR_ID = 0x0L;
        private final static long DEFAULT_OUT_PORT = 0x0L;
        private final static long DEFAULT_OUT_GROUP = 0x0L;
        private final static Set<OFFlowMonitorFlags> DEFAULT_FLAGS = ImmutableSet.<OFFlowMonitorFlags>of();
        private final static TableId DEFAULT_TABLE_ID = TableId.ALL;
        private final static Match DEFAULT_MATCH = OFFactoryVer15.MATCH_WILDCARD_ALL;

    // OF message fields
    private final long monitorId;
    private final long outPort;
    private final long outGroup;
    private final Set<OFFlowMonitorFlags> flags;
    private final TableId tableId;
    private final OFFlowMonitorCommand command;
    private final Match match;
//

    // package private constructor - used by readers, builders, and factory
    OFFlowMonitorEntryVer15(long monitorId, long outPort, long outGroup, Set<OFFlowMonitorFlags> flags, TableId tableId, OFFlowMonitorCommand command, Match match) {
        if(flags == null) {
            throw new NullPointerException("OFFlowMonitorEntryVer15: property flags cannot be null");
        }
        if(tableId == null) {
            throw new NullPointerException("OFFlowMonitorEntryVer15: property tableId cannot be null");
        }
        if(command == null) {
            throw new NullPointerException("OFFlowMonitorEntryVer15: property command cannot be null");
        }
        if(match == null) {
            throw new NullPointerException("OFFlowMonitorEntryVer15: property match cannot be null");
        }
        this.monitorId = U32.normalize(monitorId);
        this.outPort = U32.normalize(outPort);
        this.outGroup = U32.normalize(outGroup);
        this.flags = flags;
        this.tableId = tableId;
        this.command = command;
        this.match = match;
    }

    // Accessors for OF message fields
    @Override
    public long getMonitorId() {
        return monitorId;
    }

    @Override
    public long getOutPort() {
        return outPort;
    }

    @Override
    public long getOutGroup() {
        return outGroup;
    }

    @Override
    public Set<OFFlowMonitorFlags> getFlags() {
        return flags;
    }

    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFFlowMonitorCommand getCommand() {
        return command;
    }

    @Override
    public Match getMatch() {
        return match;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



    public OFFlowMonitorEntry.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFFlowMonitorEntry.Builder {
        final OFFlowMonitorEntryVer15 parentMessage;

        // OF message fields
        private boolean monitorIdSet;
        private long monitorId;
        private boolean outPortSet;
        private long outPort;
        private boolean outGroupSet;
        private long outGroup;
        private boolean flagsSet;
        private Set<OFFlowMonitorFlags> flags;
        private boolean tableIdSet;
        private TableId tableId;
        private boolean commandSet;
        private OFFlowMonitorCommand command;
        private boolean matchSet;
        private Match match;

        BuilderWithParent(OFFlowMonitorEntryVer15 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public long getMonitorId() {
        return monitorId;
    }

    @Override
    public OFFlowMonitorEntry.Builder setMonitorId(long monitorId) {
        this.monitorId = monitorId;
        this.monitorIdSet = true;
        return this;
    }
    @Override
    public long getOutPort() {
        return outPort;
    }

    @Override
    public OFFlowMonitorEntry.Builder setOutPort(long outPort) {
        this.outPort = outPort;
        this.outPortSet = true;
        return this;
    }
    @Override
    public long getOutGroup() {
        return outGroup;
    }

    @Override
    public OFFlowMonitorEntry.Builder setOutGroup(long outGroup) {
        this.outGroup = outGroup;
        this.outGroupSet = true;
        return this;
    }
    @Override
    public Set<OFFlowMonitorFlags> getFlags() {
        return flags;
    }

    @Override
    public OFFlowMonitorEntry.Builder setFlags(Set<OFFlowMonitorFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFFlowMonitorEntry.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public OFFlowMonitorCommand getCommand() {
        return command;
    }

    @Override
    public OFFlowMonitorEntry.Builder setCommand(OFFlowMonitorCommand command) {
        this.command = command;
        this.commandSet = true;
        return this;
    }
    @Override
    public Match getMatch() {
        return match;
    }

    @Override
    public OFFlowMonitorEntry.Builder setMatch(Match match) {
        this.match = match;
        this.matchSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



        @Override
        public OFFlowMonitorEntry build() {
                long monitorId = this.monitorIdSet ? this.monitorId : parentMessage.monitorId;
                long outPort = this.outPortSet ? this.outPort : parentMessage.outPort;
                long outGroup = this.outGroupSet ? this.outGroup : parentMessage.outGroup;
                Set<OFFlowMonitorFlags> flags = this.flagsSet ? this.flags : parentMessage.flags;
                if(flags == null)
                    throw new NullPointerException("Property flags must not be null");
                TableId tableId = this.tableIdSet ? this.tableId : parentMessage.tableId;
                if(tableId == null)
                    throw new NullPointerException("Property tableId must not be null");
                OFFlowMonitorCommand command = this.commandSet ? this.command : parentMessage.command;
                if(command == null)
                    throw new NullPointerException("Property command must not be null");
                Match match = this.matchSet ? this.match : parentMessage.match;
                if(match == null)
                    throw new NullPointerException("Property match must not be null");

                //
                return new OFFlowMonitorEntryVer15(
                    monitorId,
                    outPort,
                    outGroup,
                    flags,
                    tableId,
                    command,
                    match
                );
        }

    }

    static class Builder implements OFFlowMonitorEntry.Builder {
        // OF message fields
        private boolean monitorIdSet;
        private long monitorId;
        private boolean outPortSet;
        private long outPort;
        private boolean outGroupSet;
        private long outGroup;
        private boolean flagsSet;
        private Set<OFFlowMonitorFlags> flags;
        private boolean tableIdSet;
        private TableId tableId;
        private boolean commandSet;
        private OFFlowMonitorCommand command;
        private boolean matchSet;
        private Match match;

    @Override
    public long getMonitorId() {
        return monitorId;
    }

    @Override
    public OFFlowMonitorEntry.Builder setMonitorId(long monitorId) {
        this.monitorId = monitorId;
        this.monitorIdSet = true;
        return this;
    }
    @Override
    public long getOutPort() {
        return outPort;
    }

    @Override
    public OFFlowMonitorEntry.Builder setOutPort(long outPort) {
        this.outPort = outPort;
        this.outPortSet = true;
        return this;
    }
    @Override
    public long getOutGroup() {
        return outGroup;
    }

    @Override
    public OFFlowMonitorEntry.Builder setOutGroup(long outGroup) {
        this.outGroup = outGroup;
        this.outGroupSet = true;
        return this;
    }
    @Override
    public Set<OFFlowMonitorFlags> getFlags() {
        return flags;
    }

    @Override
    public OFFlowMonitorEntry.Builder setFlags(Set<OFFlowMonitorFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFFlowMonitorEntry.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public OFFlowMonitorCommand getCommand() {
        return command;
    }

    @Override
    public OFFlowMonitorEntry.Builder setCommand(OFFlowMonitorCommand command) {
        this.command = command;
        this.commandSet = true;
        return this;
    }
    @Override
    public Match getMatch() {
        return match;
    }

    @Override
    public OFFlowMonitorEntry.Builder setMatch(Match match) {
        this.match = match;
        this.matchSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }

//
        @Override
        public OFFlowMonitorEntry build() {
            long monitorId = this.monitorIdSet ? this.monitorId : DEFAULT_MONITOR_ID;
            long outPort = this.outPortSet ? this.outPort : DEFAULT_OUT_PORT;
            long outGroup = this.outGroupSet ? this.outGroup : DEFAULT_OUT_GROUP;
            Set<OFFlowMonitorFlags> flags = this.flagsSet ? this.flags : DEFAULT_FLAGS;
            if(flags == null)
                throw new NullPointerException("Property flags must not be null");
            TableId tableId = this.tableIdSet ? this.tableId : DEFAULT_TABLE_ID;
            if(tableId == null)
                throw new NullPointerException("Property tableId must not be null");
            if(!this.commandSet)
                throw new IllegalStateException("Property command doesn't have default value -- must be set");
            if(command == null)
                throw new NullPointerException("Property command must not be null");
            Match match = this.matchSet ? this.match : DEFAULT_MATCH;
            if(match == null)
                throw new NullPointerException("Property match must not be null");


            return new OFFlowMonitorEntryVer15(
                    monitorId,
                    outPort,
                    outGroup,
                    flags,
                    tableId,
                    command,
                    match
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFFlowMonitorEntry> {
        @Override
        public OFFlowMonitorEntry readFrom(ByteBuf bb) throws OFParseError {
            long monitorId = U32.f(bb.readInt());
            long outPort = U32.f(bb.readInt());
            long outGroup = U32.f(bb.readInt());
            Set<OFFlowMonitorFlags> flags = OFFlowMonitorFlagsSerializerVer15.readFrom(bb);
            TableId tableId = TableId.readByte(bb);
            OFFlowMonitorCommand command = OFFlowMonitorCommandSerializerVer15.readFrom(bb);
            Match match = ChannelUtilsVer15.readOFMatch(bb);

            OFFlowMonitorEntryVer15 flowMonitorEntryVer15 = new OFFlowMonitorEntryVer15(
                    monitorId,
                      outPort,
                      outGroup,
                      flags,
                      tableId,
                      command,
                      match
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", flowMonitorEntryVer15);
            return flowMonitorEntryVer15;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFFlowMonitorEntryVer15Funnel FUNNEL = new OFFlowMonitorEntryVer15Funnel();
    static class OFFlowMonitorEntryVer15Funnel implements Funnel<OFFlowMonitorEntryVer15> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFFlowMonitorEntryVer15 message, PrimitiveSink sink) {
            sink.putLong(message.monitorId);
            sink.putLong(message.outPort);
            sink.putLong(message.outGroup);
            OFFlowMonitorFlagsSerializerVer15.putTo(message.flags, sink);
            message.tableId.putTo(sink);
            OFFlowMonitorCommandSerializerVer15.putTo(message.command, sink);
            message.match.putTo(sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFFlowMonitorEntryVer15> {
        @Override
        public void write(ByteBuf bb, OFFlowMonitorEntryVer15 message) {
            int startIndex = bb.writerIndex();
            bb.writeInt(U32.t(message.monitorId));
            bb.writeInt(U32.t(message.outPort));
            bb.writeInt(U32.t(message.outGroup));
            OFFlowMonitorFlagsSerializerVer15.writeTo(bb, message.flags);
            message.tableId.writeByte(bb);
            OFFlowMonitorCommandSerializerVer15.writeTo(bb, message.command);
            message.match.writeTo(bb);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFFlowMonitorEntryVer15(");
        b.append("monitorId=").append(monitorId);
        b.append(", ");
        b.append("outPort=").append(outPort);
        b.append(", ");
        b.append("outGroup=").append(outGroup);
        b.append(", ");
        b.append("flags=").append(flags);
        b.append(", ");
        b.append("tableId=").append(tableId);
        b.append(", ");
        b.append("command=").append(command);
        b.append(", ");
        b.append("match=").append(match);
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
        OFFlowMonitorEntryVer15 other = (OFFlowMonitorEntryVer15) obj;

        if( monitorId != other.monitorId)
            return false;
        if( outPort != other.outPort)
            return false;
        if( outGroup != other.outGroup)
            return false;
        if (flags == null) {
            if (other.flags != null)
                return false;
        } else if (!flags.equals(other.flags))
            return false;
        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if (command == null) {
            if (other.command != null)
                return false;
        } else if (!command.equals(other.command))
            return false;
        if (match == null) {
            if (other.match != null)
                return false;
        } else if (!match.equals(other.match))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (monitorId ^ (monitorId >>> 32));
        result = prime *  (int) (outPort ^ (outPort >>> 32));
        result = prime *  (int) (outGroup ^ (outGroup >>> 32));
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime * result + ((command == null) ? 0 : command.hashCode());
        result = prime * result + ((match == null) ? 0 : match.hashCode());
        return result;
    }

}
