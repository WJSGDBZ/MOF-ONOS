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
import java.util.Set;
import com.google.common.collect.ImmutableSet;
import java.util.List;
import com.google.common.collect.ImmutableList;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFFlowDeleteVer11 implements OFFlowDelete {
    private static final Logger logger = LoggerFactory.getLogger(OFFlowDeleteVer11.class);
    // version: 1.1
    final static byte WIRE_VERSION = 2;
    final static int MINIMUM_LENGTH = 136;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static long DEFAULT_XID = 0x0L;
        private final static U64 DEFAULT_COOKIE = U64.ZERO;
        private final static U64 DEFAULT_COOKIE_MASK = U64.ZERO;
        private final static TableId DEFAULT_TABLE_ID = TableId.ZERO;
        private final static int DEFAULT_IDLE_TIMEOUT = 0x0;
        private final static int DEFAULT_HARD_TIMEOUT = 0x0;
        private final static int DEFAULT_PRIORITY = 0x0;
        private final static OFBufferId DEFAULT_BUFFER_ID = OFBufferId.NO_BUFFER;
        private final static OFPort DEFAULT_OUT_PORT = OFPort.ANY;
        private final static OFGroup DEFAULT_OUT_GROUP = OFGroup.ANY;
        private final static Set<OFFlowModFlags> DEFAULT_FLAGS = ImmutableSet.<OFFlowModFlags>of();
        private final static Match DEFAULT_MATCH = OFFactoryVer11.MATCH_WILDCARD_ALL;
        private final static List<OFInstruction> DEFAULT_INSTRUCTIONS = ImmutableList.<OFInstruction>of();

    // OF message fields
    private final long xid;
    private final U64 cookie;
    private final U64 cookieMask;
    private final TableId tableId;
    private final int idleTimeout;
    private final int hardTimeout;
    private final int priority;
    private final OFBufferId bufferId;
    private final OFPort outPort;
    private final OFGroup outGroup;
    private final Set<OFFlowModFlags> flags;
    private final Match match;
    private final List<OFInstruction> instructions;
//
    // Immutable default instance
    final static OFFlowDeleteVer11 DEFAULT = new OFFlowDeleteVer11(
        DEFAULT_XID, DEFAULT_COOKIE, DEFAULT_COOKIE_MASK, DEFAULT_TABLE_ID, DEFAULT_IDLE_TIMEOUT, DEFAULT_HARD_TIMEOUT, DEFAULT_PRIORITY, DEFAULT_BUFFER_ID, DEFAULT_OUT_PORT, DEFAULT_OUT_GROUP, DEFAULT_FLAGS, DEFAULT_MATCH, DEFAULT_INSTRUCTIONS
    );

    // package private constructor - used by readers, builders, and factory
    OFFlowDeleteVer11(long xid, U64 cookie, U64 cookieMask, TableId tableId, int idleTimeout, int hardTimeout, int priority, OFBufferId bufferId, OFPort outPort, OFGroup outGroup, Set<OFFlowModFlags> flags, Match match, List<OFInstruction> instructions) {
        if(cookie == null) {
            throw new NullPointerException("OFFlowDeleteVer11: property cookie cannot be null");
        }
        if(cookieMask == null) {
            throw new NullPointerException("OFFlowDeleteVer11: property cookieMask cannot be null");
        }
        if(tableId == null) {
            throw new NullPointerException("OFFlowDeleteVer11: property tableId cannot be null");
        }
        if(bufferId == null) {
            throw new NullPointerException("OFFlowDeleteVer11: property bufferId cannot be null");
        }
        if(outPort == null) {
            throw new NullPointerException("OFFlowDeleteVer11: property outPort cannot be null");
        }
        if(outGroup == null) {
            throw new NullPointerException("OFFlowDeleteVer11: property outGroup cannot be null");
        }
        if(flags == null) {
            throw new NullPointerException("OFFlowDeleteVer11: property flags cannot be null");
        }
        if(match == null) {
            throw new NullPointerException("OFFlowDeleteVer11: property match cannot be null");
        }
        if(instructions == null) {
            throw new NullPointerException("OFFlowDeleteVer11: property instructions cannot be null");
        }
        this.xid = U32.normalize(xid);
        this.cookie = cookie;
        this.cookieMask = cookieMask;
        this.tableId = tableId;
        this.idleTimeout = U16.normalize(idleTimeout);
        this.hardTimeout = U16.normalize(hardTimeout);
        this.priority = U16.normalize(priority);
        this.bufferId = bufferId;
        this.outPort = outPort;
        this.outGroup = outGroup;
        this.flags = flags;
        this.match = match;
        this.instructions = instructions;
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }

    @Override
    public OFType getType() {
        return OFType.FLOW_MOD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public Match getMatch() {
        return match;
    }

    @Override
    public U64 getCookie() {
        return cookie;
    }

    @Override
    public OFFlowModCommand getCommand() {
        return OFFlowModCommand.DELETE;
    }

    @Override
    public int getIdleTimeout() {
        return idleTimeout;
    }

    @Override
    public int getHardTimeout() {
        return hardTimeout;
    }

    @Override
    public int getPriority() {
        return priority;
    }

    @Override
    public OFBufferId getBufferId() {
        return bufferId;
    }

    @Override
    public OFPort getOutPort() {
        return outPort;
    }

    @Override
    public Set<OFFlowModFlags> getFlags() {
        return flags;
    }

    @Override
    public List<OFAction> getActions()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property actions not supported in version 1.1");
    }

    @Override
    public U64 getCookieMask() {
        return cookieMask;
    }

    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFGroup getOutGroup() {
        return outGroup;
    }

    @Override
    public List<OFInstruction> getInstructions() {
        return instructions;
    }

    @Override
    public int getImportance()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property importance not supported in version 1.1");
    }



    public OFFlowDelete.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFFlowDelete.Builder {
        final OFFlowDeleteVer11 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean cookieSet;
        private U64 cookie;
        private boolean cookieMaskSet;
        private U64 cookieMask;
        private boolean tableIdSet;
        private TableId tableId;
        private boolean idleTimeoutSet;
        private int idleTimeout;
        private boolean hardTimeoutSet;
        private int hardTimeout;
        private boolean prioritySet;
        private int priority;
        private boolean bufferIdSet;
        private OFBufferId bufferId;
        private boolean outPortSet;
        private OFPort outPort;
        private boolean outGroupSet;
        private OFGroup outGroup;
        private boolean flagsSet;
        private Set<OFFlowModFlags> flags;
        private boolean matchSet;
        private Match match;
        private boolean instructionsSet;
        private List<OFInstruction> instructions;

        BuilderWithParent(OFFlowDeleteVer11 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }

    @Override
    public OFType getType() {
        return OFType.FLOW_MOD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFFlowDelete.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public Match getMatch() {
        return match;
    }

    @Override
    public OFFlowDelete.Builder setMatch(Match match) {
        this.match = match;
        this.matchSet = true;
        return this;
    }
    @Override
    public U64 getCookie() {
        return cookie;
    }

    @Override
    public OFFlowDelete.Builder setCookie(U64 cookie) {
        this.cookie = cookie;
        this.cookieSet = true;
        return this;
    }
    @Override
    public OFFlowModCommand getCommand() {
        return OFFlowModCommand.DELETE;
    }

    @Override
    public int getIdleTimeout() {
        return idleTimeout;
    }

    @Override
    public OFFlowDelete.Builder setIdleTimeout(int idleTimeout) {
        this.idleTimeout = idleTimeout;
        this.idleTimeoutSet = true;
        return this;
    }
    @Override
    public int getHardTimeout() {
        return hardTimeout;
    }

    @Override
    public OFFlowDelete.Builder setHardTimeout(int hardTimeout) {
        this.hardTimeout = hardTimeout;
        this.hardTimeoutSet = true;
        return this;
    }
    @Override
    public int getPriority() {
        return priority;
    }

    @Override
    public OFFlowDelete.Builder setPriority(int priority) {
        this.priority = priority;
        this.prioritySet = true;
        return this;
    }
    @Override
    public OFBufferId getBufferId() {
        return bufferId;
    }

    @Override
    public OFFlowDelete.Builder setBufferId(OFBufferId bufferId) {
        this.bufferId = bufferId;
        this.bufferIdSet = true;
        return this;
    }
    @Override
    public OFPort getOutPort() {
        return outPort;
    }

    @Override
    public OFFlowDelete.Builder setOutPort(OFPort outPort) {
        this.outPort = outPort;
        this.outPortSet = true;
        return this;
    }
    @Override
    public Set<OFFlowModFlags> getFlags() {
        return flags;
    }

    @Override
    public OFFlowDelete.Builder setFlags(Set<OFFlowModFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public List<OFAction> getActions()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property actions not supported in version 1.1");
    }

    @Override
    public OFFlowDelete.Builder setActions(List<OFAction> actions) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property actions not supported in version 1.1");
    }
    @Override
    public U64 getCookieMask() {
        return cookieMask;
    }

    @Override
    public OFFlowDelete.Builder setCookieMask(U64 cookieMask) {
        this.cookieMask = cookieMask;
        this.cookieMaskSet = true;
        return this;
    }
    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFFlowDelete.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public OFGroup getOutGroup() {
        return outGroup;
    }

    @Override
    public OFFlowDelete.Builder setOutGroup(OFGroup outGroup) {
        this.outGroup = outGroup;
        this.outGroupSet = true;
        return this;
    }
    @Override
    public List<OFInstruction> getInstructions() {
        return instructions;
    }

    @Override
    public OFFlowDelete.Builder setInstructions(List<OFInstruction> instructions) {
        this.instructions = instructions;
        this.instructionsSet = true;
        return this;
    }
    @Override
    public int getImportance()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property importance not supported in version 1.1");
    }

    @Override
    public OFFlowDelete.Builder setImportance(int importance) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property importance not supported in version 1.1");
    }


        @Override
        public OFFlowDelete build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                U64 cookie = this.cookieSet ? this.cookie : parentMessage.cookie;
                if(cookie == null)
                    throw new NullPointerException("Property cookie must not be null");
                U64 cookieMask = this.cookieMaskSet ? this.cookieMask : parentMessage.cookieMask;
                if(cookieMask == null)
                    throw new NullPointerException("Property cookieMask must not be null");
                TableId tableId = this.tableIdSet ? this.tableId : parentMessage.tableId;
                if(tableId == null)
                    throw new NullPointerException("Property tableId must not be null");
                int idleTimeout = this.idleTimeoutSet ? this.idleTimeout : parentMessage.idleTimeout;
                int hardTimeout = this.hardTimeoutSet ? this.hardTimeout : parentMessage.hardTimeout;
                int priority = this.prioritySet ? this.priority : parentMessage.priority;
                OFBufferId bufferId = this.bufferIdSet ? this.bufferId : parentMessage.bufferId;
                if(bufferId == null)
                    throw new NullPointerException("Property bufferId must not be null");
                OFPort outPort = this.outPortSet ? this.outPort : parentMessage.outPort;
                if(outPort == null)
                    throw new NullPointerException("Property outPort must not be null");
                OFGroup outGroup = this.outGroupSet ? this.outGroup : parentMessage.outGroup;
                if(outGroup == null)
                    throw new NullPointerException("Property outGroup must not be null");
                Set<OFFlowModFlags> flags = this.flagsSet ? this.flags : parentMessage.flags;
                if(flags == null)
                    throw new NullPointerException("Property flags must not be null");
                Match match = this.matchSet ? this.match : parentMessage.match;
                if(match == null)
                    throw new NullPointerException("Property match must not be null");
                List<OFInstruction> instructions = this.instructionsSet ? this.instructions : parentMessage.instructions;
                if(instructions == null)
                    throw new NullPointerException("Property instructions must not be null");

                //
                return new OFFlowDeleteVer11(
                    xid,
                    cookie,
                    cookieMask,
                    tableId,
                    idleTimeout,
                    hardTimeout,
                    priority,
                    bufferId,
                    outPort,
                    outGroup,
                    flags,
                    match,
                    instructions
                );
        }

    }

    static class Builder implements OFFlowDelete.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean cookieSet;
        private U64 cookie;
        private boolean cookieMaskSet;
        private U64 cookieMask;
        private boolean tableIdSet;
        private TableId tableId;
        private boolean idleTimeoutSet;
        private int idleTimeout;
        private boolean hardTimeoutSet;
        private int hardTimeout;
        private boolean prioritySet;
        private int priority;
        private boolean bufferIdSet;
        private OFBufferId bufferId;
        private boolean outPortSet;
        private OFPort outPort;
        private boolean outGroupSet;
        private OFGroup outGroup;
        private boolean flagsSet;
        private Set<OFFlowModFlags> flags;
        private boolean matchSet;
        private Match match;
        private boolean instructionsSet;
        private List<OFInstruction> instructions;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }

    @Override
    public OFType getType() {
        return OFType.FLOW_MOD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFFlowDelete.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public Match getMatch() {
        return match;
    }

    @Override
    public OFFlowDelete.Builder setMatch(Match match) {
        this.match = match;
        this.matchSet = true;
        return this;
    }
    @Override
    public U64 getCookie() {
        return cookie;
    }

    @Override
    public OFFlowDelete.Builder setCookie(U64 cookie) {
        this.cookie = cookie;
        this.cookieSet = true;
        return this;
    }
    @Override
    public OFFlowModCommand getCommand() {
        return OFFlowModCommand.DELETE;
    }

    @Override
    public int getIdleTimeout() {
        return idleTimeout;
    }

    @Override
    public OFFlowDelete.Builder setIdleTimeout(int idleTimeout) {
        this.idleTimeout = idleTimeout;
        this.idleTimeoutSet = true;
        return this;
    }
    @Override
    public int getHardTimeout() {
        return hardTimeout;
    }

    @Override
    public OFFlowDelete.Builder setHardTimeout(int hardTimeout) {
        this.hardTimeout = hardTimeout;
        this.hardTimeoutSet = true;
        return this;
    }
    @Override
    public int getPriority() {
        return priority;
    }

    @Override
    public OFFlowDelete.Builder setPriority(int priority) {
        this.priority = priority;
        this.prioritySet = true;
        return this;
    }
    @Override
    public OFBufferId getBufferId() {
        return bufferId;
    }

    @Override
    public OFFlowDelete.Builder setBufferId(OFBufferId bufferId) {
        this.bufferId = bufferId;
        this.bufferIdSet = true;
        return this;
    }
    @Override
    public OFPort getOutPort() {
        return outPort;
    }

    @Override
    public OFFlowDelete.Builder setOutPort(OFPort outPort) {
        this.outPort = outPort;
        this.outPortSet = true;
        return this;
    }
    @Override
    public Set<OFFlowModFlags> getFlags() {
        return flags;
    }

    @Override
    public OFFlowDelete.Builder setFlags(Set<OFFlowModFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public List<OFAction> getActions()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property actions not supported in version 1.1");
    }

    @Override
    public OFFlowDelete.Builder setActions(List<OFAction> actions) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property actions not supported in version 1.1");
    }
    @Override
    public U64 getCookieMask() {
        return cookieMask;
    }

    @Override
    public OFFlowDelete.Builder setCookieMask(U64 cookieMask) {
        this.cookieMask = cookieMask;
        this.cookieMaskSet = true;
        return this;
    }
    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFFlowDelete.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public OFGroup getOutGroup() {
        return outGroup;
    }

    @Override
    public OFFlowDelete.Builder setOutGroup(OFGroup outGroup) {
        this.outGroup = outGroup;
        this.outGroupSet = true;
        return this;
    }
    @Override
    public List<OFInstruction> getInstructions() {
        return instructions;
    }

    @Override
    public OFFlowDelete.Builder setInstructions(List<OFInstruction> instructions) {
        this.instructions = instructions;
        this.instructionsSet = true;
        return this;
    }
    @Override
    public int getImportance()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property importance not supported in version 1.1");
    }

    @Override
    public OFFlowDelete.Builder setImportance(int importance) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property importance not supported in version 1.1");
    }
//
        @Override
        public OFFlowDelete build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            U64 cookie = this.cookieSet ? this.cookie : DEFAULT_COOKIE;
            if(cookie == null)
                throw new NullPointerException("Property cookie must not be null");
            U64 cookieMask = this.cookieMaskSet ? this.cookieMask : DEFAULT_COOKIE_MASK;
            if(cookieMask == null)
                throw new NullPointerException("Property cookieMask must not be null");
            TableId tableId = this.tableIdSet ? this.tableId : DEFAULT_TABLE_ID;
            if(tableId == null)
                throw new NullPointerException("Property tableId must not be null");
            int idleTimeout = this.idleTimeoutSet ? this.idleTimeout : DEFAULT_IDLE_TIMEOUT;
            int hardTimeout = this.hardTimeoutSet ? this.hardTimeout : DEFAULT_HARD_TIMEOUT;
            int priority = this.prioritySet ? this.priority : DEFAULT_PRIORITY;
            OFBufferId bufferId = this.bufferIdSet ? this.bufferId : DEFAULT_BUFFER_ID;
            if(bufferId == null)
                throw new NullPointerException("Property bufferId must not be null");
            OFPort outPort = this.outPortSet ? this.outPort : DEFAULT_OUT_PORT;
            if(outPort == null)
                throw new NullPointerException("Property outPort must not be null");
            OFGroup outGroup = this.outGroupSet ? this.outGroup : DEFAULT_OUT_GROUP;
            if(outGroup == null)
                throw new NullPointerException("Property outGroup must not be null");
            Set<OFFlowModFlags> flags = this.flagsSet ? this.flags : DEFAULT_FLAGS;
            if(flags == null)
                throw new NullPointerException("Property flags must not be null");
            Match match = this.matchSet ? this.match : DEFAULT_MATCH;
            if(match == null)
                throw new NullPointerException("Property match must not be null");
            List<OFInstruction> instructions = this.instructionsSet ? this.instructions : DEFAULT_INSTRUCTIONS;
            if(instructions == null)
                throw new NullPointerException("Property instructions must not be null");


            return new OFFlowDeleteVer11(
                    xid,
                    cookie,
                    cookieMask,
                    tableId,
                    idleTimeout,
                    hardTimeout,
                    priority,
                    bufferId,
                    outPort,
                    outGroup,
                    flags,
                    match,
                    instructions
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFFlowDelete> {
        @Override
        public OFFlowDelete readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 2
            byte version = bb.readByte();
            if(version != (byte) 0x2)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_11(2), got="+version);
            // fixed value property type == 14
            byte type = bb.readByte();
            if(type != (byte) 0xe)
                throw new OFParseError("Wrong type: Expected=OFType.FLOW_MOD(14), got="+type);
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
            U64 cookie = U64.ofRaw(bb.readLong());
            U64 cookieMask = U64.ofRaw(bb.readLong());
            TableId tableId = TableId.readByte(bb);
            // fixed value property command == 3
            short command = bb.readByte();
            if(command != (short) 0x3)
                throw new OFParseError("Wrong command: Expected=OFFlowModCommand.DELETE(3), got="+command);
            int idleTimeout = U16.f(bb.readShort());
            int hardTimeout = U16.f(bb.readShort());
            int priority = U16.f(bb.readShort());
            OFBufferId bufferId = OFBufferId.of(bb.readInt());
            OFPort outPort = OFPort.read4Bytes(bb);
            OFGroup outGroup = OFGroup.read4Bytes(bb);
            Set<OFFlowModFlags> flags = OFFlowModFlagsSerializerVer11.readFrom(bb);
            // pad: 2 bytes
            bb.skipBytes(2);
            Match match = ChannelUtilsVer11.readOFMatch(bb);
            List<OFInstruction> instructions = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), OFInstructionVer11.READER);

            OFFlowDeleteVer11 flowDeleteVer11 = new OFFlowDeleteVer11(
                    xid,
                      cookie,
                      cookieMask,
                      tableId,
                      idleTimeout,
                      hardTimeout,
                      priority,
                      bufferId,
                      outPort,
                      outGroup,
                      flags,
                      match,
                      instructions
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", flowDeleteVer11);
            return flowDeleteVer11;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFFlowDeleteVer11Funnel FUNNEL = new OFFlowDeleteVer11Funnel();
    static class OFFlowDeleteVer11Funnel implements Funnel<OFFlowDeleteVer11> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFFlowDeleteVer11 message, PrimitiveSink sink) {
            // fixed value property version = 2
            sink.putByte((byte) 0x2);
            // fixed value property type = 14
            sink.putByte((byte) 0xe);
            // FIXME: skip funnel of length
            sink.putLong(message.xid);
            message.cookie.putTo(sink);
            message.cookieMask.putTo(sink);
            message.tableId.putTo(sink);
            // fixed value property command = 3
            sink.putShort((short) 0x3);
            sink.putInt(message.idleTimeout);
            sink.putInt(message.hardTimeout);
            sink.putInt(message.priority);
            message.bufferId.putTo(sink);
            message.outPort.putTo(sink);
            message.outGroup.putTo(sink);
            OFFlowModFlagsSerializerVer11.putTo(message.flags, sink);
            // skip pad (2 bytes)
            message.match.putTo(sink);
            FunnelUtils.putList(message.instructions, sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFFlowDeleteVer11> {
        @Override
        public void write(ByteBuf bb, OFFlowDeleteVer11 message) {
            int startIndex = bb.writerIndex();
            // fixed value property version = 2
            bb.writeByte((byte) 0x2);
            // fixed value property type = 14
            bb.writeByte((byte) 0xe);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            bb.writeInt(U32.t(message.xid));
            bb.writeLong(message.cookie.getValue());
            bb.writeLong(message.cookieMask.getValue());
            message.tableId.writeByte(bb);
            // fixed value property command = 3
            bb.writeByte((short) 0x3);
            bb.writeShort(U16.t(message.idleTimeout));
            bb.writeShort(U16.t(message.hardTimeout));
            bb.writeShort(U16.t(message.priority));
            bb.writeInt(message.bufferId.getInt());
            message.outPort.write4Bytes(bb);
            message.outGroup.write4Bytes(bb);
            OFFlowModFlagsSerializerVer11.writeTo(bb, message.flags);
            // pad: 2 bytes
            bb.writeZero(2);
            message.match.writeTo(bb);
            ChannelUtils.writeList(bb, message.instructions);

            // update length field
            int length = bb.writerIndex() - startIndex;
            if (length > MAXIMUM_LENGTH) {
                throw new IllegalArgumentException("OFFlowDeleteVer11: message length (" + length + ") exceeds maximum (0xFFFF)");
            }
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFFlowDeleteVer11(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("cookie=").append(cookie);
        b.append(", ");
        b.append("cookieMask=").append(cookieMask);
        b.append(", ");
        b.append("tableId=").append(tableId);
        b.append(", ");
        b.append("idleTimeout=").append(idleTimeout);
        b.append(", ");
        b.append("hardTimeout=").append(hardTimeout);
        b.append(", ");
        b.append("priority=").append(priority);
        b.append(", ");
        b.append("bufferId=").append(bufferId);
        b.append(", ");
        b.append("outPort=").append(outPort);
        b.append(", ");
        b.append("outGroup=").append(outGroup);
        b.append(", ");
        b.append("flags=").append(flags);
        b.append(", ");
        b.append("match=").append(match);
        b.append(", ");
        b.append("instructions=").append(instructions);
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
        OFFlowDeleteVer11 other = (OFFlowDeleteVer11) obj;

        if( xid != other.xid)
            return false;
        if (cookie == null) {
            if (other.cookie != null)
                return false;
        } else if (!cookie.equals(other.cookie))
            return false;
        if (cookieMask == null) {
            if (other.cookieMask != null)
                return false;
        } else if (!cookieMask.equals(other.cookieMask))
            return false;
        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if( idleTimeout != other.idleTimeout)
            return false;
        if( hardTimeout != other.hardTimeout)
            return false;
        if( priority != other.priority)
            return false;
        if (bufferId == null) {
            if (other.bufferId != null)
                return false;
        } else if (!bufferId.equals(other.bufferId))
            return false;
        if (outPort == null) {
            if (other.outPort != null)
                return false;
        } else if (!outPort.equals(other.outPort))
            return false;
        if (outGroup == null) {
            if (other.outGroup != null)
                return false;
        } else if (!outGroup.equals(other.outGroup))
            return false;
        if (flags == null) {
            if (other.flags != null)
                return false;
        } else if (!flags.equals(other.flags))
            return false;
        if (match == null) {
            if (other.match != null)
                return false;
        } else if (!match.equals(other.match))
            return false;
        if (instructions == null) {
            if (other.instructions != null)
                return false;
        } else if (!instructions.equals(other.instructions))
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
        OFFlowDeleteVer11 other = (OFFlowDeleteVer11) obj;

        // ignore XID
        if (cookie == null) {
            if (other.cookie != null)
                return false;
        } else if (!cookie.equals(other.cookie))
            return false;
        if (cookieMask == null) {
            if (other.cookieMask != null)
                return false;
        } else if (!cookieMask.equals(other.cookieMask))
            return false;
        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if( idleTimeout != other.idleTimeout)
            return false;
        if( hardTimeout != other.hardTimeout)
            return false;
        if( priority != other.priority)
            return false;
        if (bufferId == null) {
            if (other.bufferId != null)
                return false;
        } else if (!bufferId.equals(other.bufferId))
            return false;
        if (outPort == null) {
            if (other.outPort != null)
                return false;
        } else if (!outPort.equals(other.outPort))
            return false;
        if (outGroup == null) {
            if (other.outGroup != null)
                return false;
        } else if (!outGroup.equals(other.outGroup))
            return false;
        if (flags == null) {
            if (other.flags != null)
                return false;
        } else if (!flags.equals(other.flags))
            return false;
        if (match == null) {
            if (other.match != null)
                return false;
        } else if (!match.equals(other.match))
            return false;
        if (instructions == null) {
            if (other.instructions != null)
                return false;
        } else if (!instructions.equals(other.instructions))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime * result + ((cookie == null) ? 0 : cookie.hashCode());
        result = prime * result + ((cookieMask == null) ? 0 : cookieMask.hashCode());
        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime * result + idleTimeout;
        result = prime * result + hardTimeout;
        result = prime * result + priority;
        result = prime * result + ((bufferId == null) ? 0 : bufferId.hashCode());
        result = prime * result + ((outPort == null) ? 0 : outPort.hashCode());
        result = prime * result + ((outGroup == null) ? 0 : outGroup.hashCode());
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((match == null) ? 0 : match.hashCode());
        result = prime * result + ((instructions == null) ? 0 : instructions.hashCode());
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + ((cookie == null) ? 0 : cookie.hashCode());
        result = prime * result + ((cookieMask == null) ? 0 : cookieMask.hashCode());
        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime * result + idleTimeout;
        result = prime * result + hardTimeout;
        result = prime * result + priority;
        result = prime * result + ((bufferId == null) ? 0 : bufferId.hashCode());
        result = prime * result + ((outPort == null) ? 0 : outPort.hashCode());
        result = prime * result + ((outGroup == null) ? 0 : outGroup.hashCode());
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((match == null) ? 0 : match.hashCode());
        result = prime * result + ((instructions == null) ? 0 : instructions.hashCode());
        return result;
    }

}
