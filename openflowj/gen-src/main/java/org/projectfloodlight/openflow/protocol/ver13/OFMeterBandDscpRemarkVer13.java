// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver13;

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

class OFMeterBandDscpRemarkVer13 implements OFMeterBandDscpRemark {
    private static final Logger logger = LoggerFactory.getLogger(OFMeterBandDscpRemarkVer13.class);
    // version: 1.3
    final static byte WIRE_VERSION = 4;
    final static int LENGTH = 16;

        private final static long DEFAULT_RATE = 0x0L;
        private final static long DEFAULT_BURST_SIZE = 0x0L;
        private final static short DEFAULT_PREC_LEVEL = (short) 0x0;

    // OF message fields
    private final long rate;
    private final long burstSize;
    private final short precLevel;
//
    // Immutable default instance
    final static OFMeterBandDscpRemarkVer13 DEFAULT = new OFMeterBandDscpRemarkVer13(
        DEFAULT_RATE, DEFAULT_BURST_SIZE, DEFAULT_PREC_LEVEL
    );

    // package private constructor - used by readers, builders, and factory
    OFMeterBandDscpRemarkVer13(long rate, long burstSize, short precLevel) {
        this.rate = U32.normalize(rate);
        this.burstSize = U32.normalize(burstSize);
        this.precLevel = U8.normalize(precLevel);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x2;
    }

    @Override
    public long getRate() {
        return rate;
    }

    @Override
    public long getBurstSize() {
        return burstSize;
    }

    @Override
    public short getPrecLevel() {
        return precLevel;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



    public OFMeterBandDscpRemark.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFMeterBandDscpRemark.Builder {
        final OFMeterBandDscpRemarkVer13 parentMessage;

        // OF message fields
        private boolean rateSet;
        private long rate;
        private boolean burstSizeSet;
        private long burstSize;
        private boolean precLevelSet;
        private short precLevel;

        BuilderWithParent(OFMeterBandDscpRemarkVer13 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x2;
    }

    @Override
    public long getRate() {
        return rate;
    }

    @Override
    public OFMeterBandDscpRemark.Builder setRate(long rate) {
        this.rate = rate;
        this.rateSet = true;
        return this;
    }
    @Override
    public long getBurstSize() {
        return burstSize;
    }

    @Override
    public OFMeterBandDscpRemark.Builder setBurstSize(long burstSize) {
        this.burstSize = burstSize;
        this.burstSizeSet = true;
        return this;
    }
    @Override
    public short getPrecLevel() {
        return precLevel;
    }

    @Override
    public OFMeterBandDscpRemark.Builder setPrecLevel(short precLevel) {
        this.precLevel = precLevel;
        this.precLevelSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }



        @Override
        public OFMeterBandDscpRemark build() {
                long rate = this.rateSet ? this.rate : parentMessage.rate;
                long burstSize = this.burstSizeSet ? this.burstSize : parentMessage.burstSize;
                short precLevel = this.precLevelSet ? this.precLevel : parentMessage.precLevel;

                //
                return new OFMeterBandDscpRemarkVer13(
                    rate,
                    burstSize,
                    precLevel
                );
        }

    }

    static class Builder implements OFMeterBandDscpRemark.Builder {
        // OF message fields
        private boolean rateSet;
        private long rate;
        private boolean burstSizeSet;
        private long burstSize;
        private boolean precLevelSet;
        private short precLevel;

    @Override
    public int getType() {
        return 0x2;
    }

    @Override
    public long getRate() {
        return rate;
    }

    @Override
    public OFMeterBandDscpRemark.Builder setRate(long rate) {
        this.rate = rate;
        this.rateSet = true;
        return this;
    }
    @Override
    public long getBurstSize() {
        return burstSize;
    }

    @Override
    public OFMeterBandDscpRemark.Builder setBurstSize(long burstSize) {
        this.burstSize = burstSize;
        this.burstSizeSet = true;
        return this;
    }
    @Override
    public short getPrecLevel() {
        return precLevel;
    }

    @Override
    public OFMeterBandDscpRemark.Builder setPrecLevel(short precLevel) {
        this.precLevel = precLevel;
        this.precLevelSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_13;
    }

//
        @Override
        public OFMeterBandDscpRemark build() {
            long rate = this.rateSet ? this.rate : DEFAULT_RATE;
            long burstSize = this.burstSizeSet ? this.burstSize : DEFAULT_BURST_SIZE;
            short precLevel = this.precLevelSet ? this.precLevel : DEFAULT_PREC_LEVEL;


            return new OFMeterBandDscpRemarkVer13(
                    rate,
                    burstSize,
                    precLevel
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFMeterBandDscpRemark> {
        @Override
        public OFMeterBandDscpRemark readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x2
            short type = bb.readShort();
            if(type != (short) 0x2)
                throw new OFParseError("Wrong type: Expected=0x2(0x2), got="+type);
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
            long rate = U32.f(bb.readInt());
            long burstSize = U32.f(bb.readInt());
            short precLevel = U8.f(bb.readByte());
            // pad: 3 bytes
            bb.skipBytes(3);

            OFMeterBandDscpRemarkVer13 meterBandDscpRemarkVer13 = new OFMeterBandDscpRemarkVer13(
                    rate,
                      burstSize,
                      precLevel
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", meterBandDscpRemarkVer13);
            return meterBandDscpRemarkVer13;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFMeterBandDscpRemarkVer13Funnel FUNNEL = new OFMeterBandDscpRemarkVer13Funnel();
    static class OFMeterBandDscpRemarkVer13Funnel implements Funnel<OFMeterBandDscpRemarkVer13> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFMeterBandDscpRemarkVer13 message, PrimitiveSink sink) {
            // fixed value property type = 0x2
            sink.putShort((short) 0x2);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            sink.putLong(message.rate);
            sink.putLong(message.burstSize);
            sink.putShort(message.precLevel);
            // skip pad (3 bytes)
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFMeterBandDscpRemarkVer13> {
        @Override
        public void write(ByteBuf bb, OFMeterBandDscpRemarkVer13 message) {
            // fixed value property type = 0x2
            bb.writeShort((short) 0x2);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            bb.writeInt(U32.t(message.rate));
            bb.writeInt(U32.t(message.burstSize));
            bb.writeByte(U8.t(message.precLevel));
            // pad: 3 bytes
            bb.writeZero(3);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFMeterBandDscpRemarkVer13(");
        b.append("rate=").append(rate);
        b.append(", ");
        b.append("burstSize=").append(burstSize);
        b.append(", ");
        b.append("precLevel=").append(precLevel);
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
        OFMeterBandDscpRemarkVer13 other = (OFMeterBandDscpRemarkVer13) obj;

        if( rate != other.rate)
            return false;
        if( burstSize != other.burstSize)
            return false;
        if( precLevel != other.precLevel)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (rate ^ (rate >>> 32));
        result = prime *  (int) (burstSize ^ (burstSize >>> 32));
        result = prime * result + precLevel;
        return result;
    }

}
