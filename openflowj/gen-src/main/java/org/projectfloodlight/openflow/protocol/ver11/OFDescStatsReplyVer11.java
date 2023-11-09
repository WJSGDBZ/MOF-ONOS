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
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFDescStatsReplyVer11 implements OFDescStatsReply {
    private static final Logger logger = LoggerFactory.getLogger(OFDescStatsReplyVer11.class);
    // version: 1.1
    final static byte WIRE_VERSION = 2;
    final static int LENGTH = 1072;

        private final static long DEFAULT_XID = 0x0L;
        private final static Set<OFStatsReplyFlags> DEFAULT_FLAGS = ImmutableSet.<OFStatsReplyFlags>of();
        private final static String DEFAULT_MFR_DESC = "";
        private final static String DEFAULT_HW_DESC = "";
        private final static String DEFAULT_SW_DESC = "";
        private final static String DEFAULT_SERIAL_NUM = "";
        private final static String DEFAULT_DP_DESC = "";

    // OF message fields
    private final long xid;
    private final Set<OFStatsReplyFlags> flags;
    private final String mfrDesc;
    private final String hwDesc;
    private final String swDesc;
    private final String serialNum;
    private final String dpDesc;
//
    // Immutable default instance
    final static OFDescStatsReplyVer11 DEFAULT = new OFDescStatsReplyVer11(
        DEFAULT_XID, DEFAULT_FLAGS, DEFAULT_MFR_DESC, DEFAULT_HW_DESC, DEFAULT_SW_DESC, DEFAULT_SERIAL_NUM, DEFAULT_DP_DESC
    );

    // package private constructor - used by readers, builders, and factory
    OFDescStatsReplyVer11(long xid, Set<OFStatsReplyFlags> flags, String mfrDesc, String hwDesc, String swDesc, String serialNum, String dpDesc) {
        if(flags == null) {
            throw new NullPointerException("OFDescStatsReplyVer11: property flags cannot be null");
        }
        if(mfrDesc == null) {
            throw new NullPointerException("OFDescStatsReplyVer11: property mfrDesc cannot be null");
        }
        if(hwDesc == null) {
            throw new NullPointerException("OFDescStatsReplyVer11: property hwDesc cannot be null");
        }
        if(swDesc == null) {
            throw new NullPointerException("OFDescStatsReplyVer11: property swDesc cannot be null");
        }
        if(serialNum == null) {
            throw new NullPointerException("OFDescStatsReplyVer11: property serialNum cannot be null");
        }
        if(dpDesc == null) {
            throw new NullPointerException("OFDescStatsReplyVer11: property dpDesc cannot be null");
        }
        this.xid = U32.normalize(xid);
        this.flags = flags;
        this.mfrDesc = mfrDesc;
        this.hwDesc = hwDesc;
        this.swDesc = swDesc;
        this.serialNum = serialNum;
        this.dpDesc = dpDesc;
    }

    // Accessors for OF message fields
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
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
        return OFStatsType.DESC;
    }

    @Override
    public Set<OFStatsReplyFlags> getFlags() {
        return flags;
    }

    @Override
    public String getMfrDesc() {
        return mfrDesc;
    }

    @Override
    public String getHwDesc() {
        return hwDesc;
    }

    @Override
    public String getSwDesc() {
        return swDesc;
    }

    @Override
    public String getSerialNum() {
        return serialNum;
    }

    @Override
    public String getDpDesc() {
        return dpDesc;
    }



    public OFDescStatsReply.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFDescStatsReply.Builder {
        final OFDescStatsReplyVer11 parentMessage;

        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean flagsSet;
        private Set<OFStatsReplyFlags> flags;
        private boolean mfrDescSet;
        private String mfrDesc;
        private boolean hwDescSet;
        private String hwDesc;
        private boolean swDescSet;
        private String swDesc;
        private boolean serialNumSet;
        private String serialNum;
        private boolean dpDescSet;
        private String dpDesc;

        BuilderWithParent(OFDescStatsReplyVer11 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
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
    public OFDescStatsReply.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public OFStatsType getStatsType() {
        return OFStatsType.DESC;
    }

    @Override
    public Set<OFStatsReplyFlags> getFlags() {
        return flags;
    }

    @Override
    public OFDescStatsReply.Builder setFlags(Set<OFStatsReplyFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public String getMfrDesc() {
        return mfrDesc;
    }

    @Override
    public OFDescStatsReply.Builder setMfrDesc(String mfrDesc) {
        this.mfrDesc = mfrDesc;
        this.mfrDescSet = true;
        return this;
    }
    @Override
    public String getHwDesc() {
        return hwDesc;
    }

    @Override
    public OFDescStatsReply.Builder setHwDesc(String hwDesc) {
        this.hwDesc = hwDesc;
        this.hwDescSet = true;
        return this;
    }
    @Override
    public String getSwDesc() {
        return swDesc;
    }

    @Override
    public OFDescStatsReply.Builder setSwDesc(String swDesc) {
        this.swDesc = swDesc;
        this.swDescSet = true;
        return this;
    }
    @Override
    public String getSerialNum() {
        return serialNum;
    }

    @Override
    public OFDescStatsReply.Builder setSerialNum(String serialNum) {
        this.serialNum = serialNum;
        this.serialNumSet = true;
        return this;
    }
    @Override
    public String getDpDesc() {
        return dpDesc;
    }

    @Override
    public OFDescStatsReply.Builder setDpDesc(String dpDesc) {
        this.dpDesc = dpDesc;
        this.dpDescSet = true;
        return this;
    }


        @Override
        public OFDescStatsReply build() {
                long xid = this.xidSet ? this.xid : parentMessage.xid;
                Set<OFStatsReplyFlags> flags = this.flagsSet ? this.flags : parentMessage.flags;
                if(flags == null)
                    throw new NullPointerException("Property flags must not be null");
                String mfrDesc = this.mfrDescSet ? this.mfrDesc : parentMessage.mfrDesc;
                if(mfrDesc == null)
                    throw new NullPointerException("Property mfrDesc must not be null");
                String hwDesc = this.hwDescSet ? this.hwDesc : parentMessage.hwDesc;
                if(hwDesc == null)
                    throw new NullPointerException("Property hwDesc must not be null");
                String swDesc = this.swDescSet ? this.swDesc : parentMessage.swDesc;
                if(swDesc == null)
                    throw new NullPointerException("Property swDesc must not be null");
                String serialNum = this.serialNumSet ? this.serialNum : parentMessage.serialNum;
                if(serialNum == null)
                    throw new NullPointerException("Property serialNum must not be null");
                String dpDesc = this.dpDescSet ? this.dpDesc : parentMessage.dpDesc;
                if(dpDesc == null)
                    throw new NullPointerException("Property dpDesc must not be null");

                //
                return new OFDescStatsReplyVer11(
                    xid,
                    flags,
                    mfrDesc,
                    hwDesc,
                    swDesc,
                    serialNum,
                    dpDesc
                );
        }

    }

    static class Builder implements OFDescStatsReply.Builder {
        // OF message fields
        private boolean xidSet;
        private long xid;
        private boolean flagsSet;
        private Set<OFStatsReplyFlags> flags;
        private boolean mfrDescSet;
        private String mfrDesc;
        private boolean hwDescSet;
        private String hwDesc;
        private boolean swDescSet;
        private String swDesc;
        private boolean serialNumSet;
        private String serialNum;
        private boolean dpDescSet;
        private String dpDesc;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
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
    public OFDescStatsReply.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }
    @Override
    public OFStatsType getStatsType() {
        return OFStatsType.DESC;
    }

    @Override
    public Set<OFStatsReplyFlags> getFlags() {
        return flags;
    }

    @Override
    public OFDescStatsReply.Builder setFlags(Set<OFStatsReplyFlags> flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public String getMfrDesc() {
        return mfrDesc;
    }

    @Override
    public OFDescStatsReply.Builder setMfrDesc(String mfrDesc) {
        this.mfrDesc = mfrDesc;
        this.mfrDescSet = true;
        return this;
    }
    @Override
    public String getHwDesc() {
        return hwDesc;
    }

    @Override
    public OFDescStatsReply.Builder setHwDesc(String hwDesc) {
        this.hwDesc = hwDesc;
        this.hwDescSet = true;
        return this;
    }
    @Override
    public String getSwDesc() {
        return swDesc;
    }

    @Override
    public OFDescStatsReply.Builder setSwDesc(String swDesc) {
        this.swDesc = swDesc;
        this.swDescSet = true;
        return this;
    }
    @Override
    public String getSerialNum() {
        return serialNum;
    }

    @Override
    public OFDescStatsReply.Builder setSerialNum(String serialNum) {
        this.serialNum = serialNum;
        this.serialNumSet = true;
        return this;
    }
    @Override
    public String getDpDesc() {
        return dpDesc;
    }

    @Override
    public OFDescStatsReply.Builder setDpDesc(String dpDesc) {
        this.dpDesc = dpDesc;
        this.dpDescSet = true;
        return this;
    }
//
        @Override
        public OFDescStatsReply build() {
            long xid = this.xidSet ? this.xid : DEFAULT_XID;
            Set<OFStatsReplyFlags> flags = this.flagsSet ? this.flags : DEFAULT_FLAGS;
            if(flags == null)
                throw new NullPointerException("Property flags must not be null");
            String mfrDesc = this.mfrDescSet ? this.mfrDesc : DEFAULT_MFR_DESC;
            if(mfrDesc == null)
                throw new NullPointerException("Property mfrDesc must not be null");
            String hwDesc = this.hwDescSet ? this.hwDesc : DEFAULT_HW_DESC;
            if(hwDesc == null)
                throw new NullPointerException("Property hwDesc must not be null");
            String swDesc = this.swDescSet ? this.swDesc : DEFAULT_SW_DESC;
            if(swDesc == null)
                throw new NullPointerException("Property swDesc must not be null");
            String serialNum = this.serialNumSet ? this.serialNum : DEFAULT_SERIAL_NUM;
            if(serialNum == null)
                throw new NullPointerException("Property serialNum must not be null");
            String dpDesc = this.dpDescSet ? this.dpDesc : DEFAULT_DP_DESC;
            if(dpDesc == null)
                throw new NullPointerException("Property dpDesc must not be null");


            return new OFDescStatsReplyVer11(
                    xid,
                    flags,
                    mfrDesc,
                    hwDesc,
                    swDesc,
                    serialNum,
                    dpDesc
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFDescStatsReply> {
        @Override
        public OFDescStatsReply readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property version == 2
            byte version = bb.readByte();
            if(version != (byte) 0x2)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_11(2), got="+version);
            // fixed value property type == 19
            byte type = bb.readByte();
            if(type != (byte) 0x13)
                throw new OFParseError("Wrong type: Expected=OFType.STATS_REPLY(19), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 1072)
                throw new OFParseError("Wrong length: Expected=1072(1072), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            long xid = U32.f(bb.readInt());
            // fixed value property statsType == 0
            short statsType = bb.readShort();
            if(statsType != (short) 0x0)
                throw new OFParseError("Wrong statsType: Expected=OFStatsType.DESC(0), got="+statsType);
            Set<OFStatsReplyFlags> flags = OFStatsReplyFlagsSerializerVer11.readFrom(bb);
            // pad: 4 bytes
            bb.skipBytes(4);
            String mfrDesc = ChannelUtils.readFixedLengthString(bb, 256);
            String hwDesc = ChannelUtils.readFixedLengthString(bb, 256);
            String swDesc = ChannelUtils.readFixedLengthString(bb, 256);
            String serialNum = ChannelUtils.readFixedLengthString(bb, 32);
            String dpDesc = ChannelUtils.readFixedLengthString(bb, 256);

            OFDescStatsReplyVer11 descStatsReplyVer11 = new OFDescStatsReplyVer11(
                    xid,
                      flags,
                      mfrDesc,
                      hwDesc,
                      swDesc,
                      serialNum,
                      dpDesc
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", descStatsReplyVer11);
            return descStatsReplyVer11;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFDescStatsReplyVer11Funnel FUNNEL = new OFDescStatsReplyVer11Funnel();
    static class OFDescStatsReplyVer11Funnel implements Funnel<OFDescStatsReplyVer11> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFDescStatsReplyVer11 message, PrimitiveSink sink) {
            // fixed value property version = 2
            sink.putByte((byte) 0x2);
            // fixed value property type = 19
            sink.putByte((byte) 0x13);
            // fixed value property length = 1072
            sink.putShort((short) 0x430);
            sink.putLong(message.xid);
            // fixed value property statsType = 0
            sink.putShort((short) 0x0);
            OFStatsReplyFlagsSerializerVer11.putTo(message.flags, sink);
            // skip pad (4 bytes)
            sink.putUnencodedChars(message.mfrDesc);
            sink.putUnencodedChars(message.hwDesc);
            sink.putUnencodedChars(message.swDesc);
            sink.putUnencodedChars(message.serialNum);
            sink.putUnencodedChars(message.dpDesc);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFDescStatsReplyVer11> {
        @Override
        public void write(ByteBuf bb, OFDescStatsReplyVer11 message) {
            // fixed value property version = 2
            bb.writeByte((byte) 0x2);
            // fixed value property type = 19
            bb.writeByte((byte) 0x13);
            // fixed value property length = 1072
            bb.writeShort((short) 0x430);
            bb.writeInt(U32.t(message.xid));
            // fixed value property statsType = 0
            bb.writeShort((short) 0x0);
            OFStatsReplyFlagsSerializerVer11.writeTo(bb, message.flags);
            // pad: 4 bytes
            bb.writeZero(4);
            ChannelUtils.writeFixedLengthString(bb, message.mfrDesc, 256);
            ChannelUtils.writeFixedLengthString(bb, message.hwDesc, 256);
            ChannelUtils.writeFixedLengthString(bb, message.swDesc, 256);
            ChannelUtils.writeFixedLengthString(bb, message.serialNum, 32);
            ChannelUtils.writeFixedLengthString(bb, message.dpDesc, 256);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFDescStatsReplyVer11(");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("flags=").append(flags);
        b.append(", ");
        b.append("mfrDesc=").append(mfrDesc);
        b.append(", ");
        b.append("hwDesc=").append(hwDesc);
        b.append(", ");
        b.append("swDesc=").append(swDesc);
        b.append(", ");
        b.append("serialNum=").append(serialNum);
        b.append(", ");
        b.append("dpDesc=").append(dpDesc);
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
        OFDescStatsReplyVer11 other = (OFDescStatsReplyVer11) obj;

        if( xid != other.xid)
            return false;
        if (flags == null) {
            if (other.flags != null)
                return false;
        } else if (!flags.equals(other.flags))
            return false;
        if (mfrDesc == null) {
            if (other.mfrDesc != null)
                return false;
        } else if (!mfrDesc.equals(other.mfrDesc))
            return false;
        if (hwDesc == null) {
            if (other.hwDesc != null)
                return false;
        } else if (!hwDesc.equals(other.hwDesc))
            return false;
        if (swDesc == null) {
            if (other.swDesc != null)
                return false;
        } else if (!swDesc.equals(other.swDesc))
            return false;
        if (serialNum == null) {
            if (other.serialNum != null)
                return false;
        } else if (!serialNum.equals(other.serialNum))
            return false;
        if (dpDesc == null) {
            if (other.dpDesc != null)
                return false;
        } else if (!dpDesc.equals(other.dpDesc))
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
        OFDescStatsReplyVer11 other = (OFDescStatsReplyVer11) obj;

        // ignore XID
        if (flags == null) {
            if (other.flags != null)
                return false;
        } else if (!flags.equals(other.flags))
            return false;
        if (mfrDesc == null) {
            if (other.mfrDesc != null)
                return false;
        } else if (!mfrDesc.equals(other.mfrDesc))
            return false;
        if (hwDesc == null) {
            if (other.hwDesc != null)
                return false;
        } else if (!hwDesc.equals(other.hwDesc))
            return false;
        if (swDesc == null) {
            if (other.swDesc != null)
                return false;
        } else if (!swDesc.equals(other.swDesc))
            return false;
        if (serialNum == null) {
            if (other.serialNum != null)
                return false;
        } else if (!serialNum.equals(other.serialNum))
            return false;
        if (dpDesc == null) {
            if (other.dpDesc != null)
                return false;
        } else if (!dpDesc.equals(other.dpDesc))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (xid ^ (xid >>> 32));
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((mfrDesc == null) ? 0 : mfrDesc.hashCode());
        result = prime * result + ((hwDesc == null) ? 0 : hwDesc.hashCode());
        result = prime * result + ((swDesc == null) ? 0 : swDesc.hashCode());
        result = prime * result + ((serialNum == null) ? 0 : serialNum.hashCode());
        result = prime * result + ((dpDesc == null) ? 0 : dpDesc.hashCode());
        return result;
    }

    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((mfrDesc == null) ? 0 : mfrDesc.hashCode());
        result = prime * result + ((hwDesc == null) ? 0 : hwDesc.hashCode());
        result = prime * result + ((swDesc == null) ? 0 : swDesc.hashCode());
        result = prime * result + ((serialNum == null) ? 0 : serialNum.hashCode());
        result = prime * result + ((dpDesc == null) ? 0 : dpDesc.hashCode());
        return result;
    }

}
