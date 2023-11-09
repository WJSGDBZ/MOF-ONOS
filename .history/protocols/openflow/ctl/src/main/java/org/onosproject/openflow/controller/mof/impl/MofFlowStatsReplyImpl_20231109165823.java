package org.onosproject.openflow.controller.mof.impl;

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
import org.projectfloodlight.openflow.protocol.ver10.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Set;
import com.google.common.collect.ImmutableSet;
import java.util.List;
import com.google.common.collect.ImmutableList;
import io.netty.buffer.ByteBuf;

import org.onosproject.openflow.controller.mof.ver10.MofFlowStatsEntryVer10;
import org.onosproject.openflow.controller.mof.api.*;

import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

public class MofFlowStatsReplyImpl implements MofFlowStatsReply {
    private static final Logger logger = LoggerFactory.getLogger(MofFlowStatsReplyImpl.class);
    // version: 1.0
    final static byte WIRE_VERSION = 1;
    final static int MINIMUM_LENGTH = 12;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

    private final static long DEFAULT_XID = 0x0L;
    private final static Set<OFStatsReplyFlags> DEFAULT_FLAGS = ImmutableSet.<OFStatsReplyFlags>of();
    private final static List<MofFlowStatsEntry> DEFAULT_ENTRIES = ImmutableList.<MofFlowStatsEntry>of();

    // OF message fields
    private final long xid;
    private final Set<OFStatsReplyFlags> flags;
    private final List<MofFlowStatsEntry> entries;
    //
    // Immutable default instance
    final static MofFlowStatsReplyImpl DEFAULT = new MofFlowStatsReplyImpl(
            DEFAULT_XID, DEFAULT_FLAGS, DEFAULT_ENTRIES);

    // package private constructor - used by readers, builders, and factory
    MofFlowStatsReplyImpl(long xid, Set<OFStatsReplyFlags> flags, List<MofFlowStatsEntry> entries) {
        if(flags == null) {
            throw new NullPointerException("MofFlowStatsReplyImpl: property flags cannot be null");
        }
        if(entries == null) {
            throw new NullPointerException("MofFlowStatsReplyImpl: property entries cannot be null");
        }
        this.xid = xid & 0xFFFF_FFFFL;
        this.flags = flags;
        this.entries = entries;
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
    }

    @Override
    public OFType getType() {
        return OFType.STATS_REPLY;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public OFStatsType getStatsType() {
        return OFStatsType.FLOW;
    }

    @Override
    public Set<OFStatsReplyFlags> getFlags() {
        return flags;
    }

    @Override
    public List<MofFlowStatsEntry> getEntries() {
        return entries;
    }

    public MofFlowStatsReply.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements MofFlowStatsReply.Builder {
        final MofFlowStatsReplyImpl parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean flagsSet;
        private Set<OFStatsReplyFlags> flags;
        private boolean entriesSet;
        private List<MofFlowStatsEntry> entries;

        BuilderWithParent(MofFlowStatsReplyImpl parentMessage) {
            this.parentMessage = parentMessage;
        }

        @Override
        public OFVersion getVersion() {
            return OFVersion.OF_10;
        }

        @Override
        public OFType getType() {
            return OFType.STATS_REPLY;
        }

        @Override
        public long getXid() {
            return xid;
        }

        @Override
        public MofFlowStatsReply.Builder setXid(long xid) {
            this.xid = xid;
            this.xidSet = true;
            return this;
        }

        @Override
        public OFStatsType getStatsType() {
            return OFStatsType.FLOW;
        }

        @Override
        public Set<OFStatsReplyFlags> getFlags() {
            return flags;
        }

        @Override
        public MofFlowStatsReply.Builder setFlags(Set<OFStatsReplyFlags> flags) {
            this.flags = flags;
            this.flagsSet = true;
            return this;
        }

        @Override
        public List<MofFlowStatsEntry> getEntries() {
            return entries;
        }

        @Override
        public MofFlowStatsReply.Builder setEntries(List<MofFlowStatsEntry> entries) {
            this.entries = entries;
            this.entriesSet = true;
            return this;
        }

        @Override
        public MofFlowStatsReply build() {
            long xid = this.xidSet ? this.xid : parentMessage.xid;
            Set<OFStatsReplyFlags> flags = this.flagsSet ? this.flags : parentMessage.flags;
            if (flags == null)
                throw new NullPointerException("Property flags must not be null");
            List<MofFlowStatsEntry> entries = this.entriesSet ? this.entries : parentMessage.entries;
            if (entries == null)
                throw new NullPointerException("Property entries must not be null");

            //
            return new MofFlowStatsReplyImpl(
                    xid,
                    flags,
                    entries);
        }

    }

    public static class Builder implements MofFlowStatsReply.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean flagsSet;
        private Set<OFStatsReplyFlags> flags;
        private boolean entriesSet;
        private List<MofFlowStatsEntry> entries;

        @Override
        public OFVersion getVersion() {
            return OFVersion.OF_10;
        }

        @Override
        public OFType getType() {
            return OFType.STATS_REPLY;
        }

        @Override
        public long getXid() {
            return xid;
        }

        @Override
        public MofFlowStatsReply.Builder setXid(long xid) {
            this.xid = xid;
            this.xidSet = true;
            return this;
        }

        @Override
        public OFStatsType getStatsType() {
            return OFStatsType.FLOW;
        }

        @Override
        public Set<OFStatsReplyFlags> getFlags() {
            return flags;
        }

        @Override
        public MofFlowStatsReply.Builder setFlags(Set<OFStatsReplyFlags> flags) {
            this.flags = flags;
            this.flagsSet = true;
            return this;
        }

        @Override
        public List<MofFlowStatsEntry> getEntries() {
            return entries;
        }

        @Override
        public MofFlowStatsReplyImpl.Builder setEntries(List<MofFlowStatsEntry> entries) {
            this.entries = entries;
            this.entriesSet = true;
            return this;
        }

        //
        @Override
        public MofFlowStatsReply build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            Set<OFStatsReplyFlags> flags = this.flagsSet ? this.flags : DEFAULT_FLAGS;
            if (flags == null)
                throw new NullPointerException("Property flags must not be null");
            List<MofFlowStatsEntry> entries = this.entriesSet ? this.entries : DEFAULT_ENTRIES;
            if (entries == null)
                throw new NullPointerException("Property entries must not be null");

            return new MofFlowStatsReplyImpl(
                    xid,
                    flags,
                    entries);
        }

    }

    public final static Reader READER = new Reader();

    static class Reader implements OFMessageReader<MofFlowStatsReply> {
        @Override
        public MofFlowStatsReply readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 1
            byte version = bb.readByte();
            // fixed value property type == 83
            byte type = bb.readByte();

            int length = U16.f(bb.readShort());
            if (length < MINIMUM_LENGTH)
                throw new OFParseError("Wrong length: Expected to be >= " + MINIMUM_LENGTH + ", was: " + length);
            if (bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if (logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            long xid = U32.f(bb.readInt());
            // fixed value property statsType == 1
            short statsType = bb.readShort();
            if (statsType != (short) 0x1)
                throw new OFParseError("Wrong statsType: Expected=OFStatsType.FLOW(1), got=" + statsType);
            Set<OFStatsReplyFlags> flags = OFStatsReplyFlagsSerializerVer10.readFrom(bb);
            List<MofFlowStatsEntry> entries = ChannelUtils.readList(bb, length - (bb.readerIndex() - start),
                                                MofFlowStatsEntryVer10.READER);

            MofFlowStatsReplyImpl flowStatsReplyVer10 = new MofFlowStatsReplyImpl(xid,
                                                                                  flags,
                                                                                  entries);
            if (logger.isTraceEnabled())
                logger.trace("readFrom - read={}", flowStatsReplyVer10);

            return flowStatsReplyVer10;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFFlowStatsReplyVer10Funnel FUNNEL = new OFFlowStatsReplyVer10Funnel();

    static class OFFlowStatsReplyVer10Funnel implements Funnel<MofFlowStatsReplyImpl> {
        private static final long serialVersionUID = 1L;

        @Override
        public void funnel(MofFlowStatsReplyImpl message, PrimitiveSink sink) {
            // fixed value property version = 1
            sink.putByte((byte) 0x1);
            // fixed value property type = 17
            sink.putByte((byte) 0x11);
            // FIXME: skip funnel of length
            sink.putLong(message.xid);
            // fixed value property statsType = 1
            sink.putShort((short) 0x1);
            OFStatsReplyFlagsSerializerVer10.putTo(message.flags, sink);
            FunnelUtils.putList(message.entries, sink);
        }
    }

    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();

    static class Writer implements OFMessageWriter<MofFlowStatsReplyImpl> {
        @Override
        public void write(ByteBuf bb, MofFlowStatsReplyImpl message) {
            int startIndex = bb.writerIndex();
            // fixed value property version = 1
            bb.writeByte((byte) 0x1);
            // fixed value property type = 17
            bb.writeByte((byte) 0x11);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            bb.writeInt(U32.t(message.xid));
            // fixed value property statsType = 1
            bb.writeShort((short) 0x1);
            OFStatsReplyFlagsSerializerVer10.writeTo(bb, message.flags);
            ChannelUtils.writeList(bb, message.entries);

            // update length field
            int length = bb.writerIndex() - startIndex;
            if (length > MAXIMUM_LENGTH) {
                throw new IllegalArgumentException(
                        "MofFlowStatsReplyImpl: message length (" + length + ") exceeds maximum (0xFFFF)");
            }
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("MofFlowStatsReplyImpl(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("flags=").append(flags);
        b.append(", ");
        b.append("entries=").append(entries);
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
        MofFlowStatsReplyImpl other = (MofFlowStatsReplyImpl) obj;

        if (xid != other.xid)
            return false;
        if (flags == null) {
            if (other.flags != null)
                return false;
        } else if (!flags.equals(other.flags))
            return false;
        if (entries == null) {
            if (other.entries != null)
                return false;
        } else if (!entries.equals(other.entries))
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
        MofFlowStatsReplyImpl other = (MofFlowStatsReplyImpl) obj;

        // ignore XID
        if (flags == null) {
            if (other.flags != null)
                return false;
        } else if (!flags.equals(other.flags))
            return false;
        if (entries == null) {
            if (other.entries != null)
                return false;
        } else if (!entries.equals(other.entries))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * (int) (xid ^ (xid >>> 32));
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((entries == null) ? 0 : entries.hashCode());
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((entries == null) ? 0 : entries.hashCode());
        return result;
    }

}