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

class OFPortStatsPropOpticalVer14 implements OFPortStatsPropOptical {
    private static final Logger logger = LoggerFactory.getLogger(OFPortStatsPropOpticalVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 44;

        private final static long DEFAULT_FLAGS = 0x0L;
        private final static long DEFAULT_TX_FREQ_LMDA = 0x0L;
        private final static long DEFAULT_TX_OFFSET = 0x0L;
        private final static long DEFAULT_TX_GRID_SPAN = 0x0L;
        private final static long DEFAULT_RX_FREQ_LMDA = 0x0L;
        private final static long DEFAULT_RX_OFFSET = 0x0L;
        private final static long DEFAULT_RX_GRID_SPAN = 0x0L;
        private final static int DEFAULT_TX_PWR = 0x0;
        private final static int DEFAULT_RX_PWR = 0x0;
        private final static int DEFAULT_BIAS_CURRENT = 0x0;
        private final static int DEFAULT_TEMPERATURE = 0x0;

    // OF message fields
    private final long flags;
    private final long txFreqLmda;
    private final long txOffset;
    private final long txGridSpan;
    private final long rxFreqLmda;
    private final long rxOffset;
    private final long rxGridSpan;
    private final int txPwr;
    private final int rxPwr;
    private final int biasCurrent;
    private final int temperature;
//
    // Immutable default instance
    final static OFPortStatsPropOpticalVer14 DEFAULT = new OFPortStatsPropOpticalVer14(
        DEFAULT_FLAGS, DEFAULT_TX_FREQ_LMDA, DEFAULT_TX_OFFSET, DEFAULT_TX_GRID_SPAN, DEFAULT_RX_FREQ_LMDA, DEFAULT_RX_OFFSET, DEFAULT_RX_GRID_SPAN, DEFAULT_TX_PWR, DEFAULT_RX_PWR, DEFAULT_BIAS_CURRENT, DEFAULT_TEMPERATURE
    );

    // package private constructor - used by readers, builders, and factory
    OFPortStatsPropOpticalVer14(long flags, long txFreqLmda, long txOffset, long txGridSpan, long rxFreqLmda, long rxOffset, long rxGridSpan, int txPwr, int rxPwr, int biasCurrent, int temperature) {
        this.flags = U32.normalize(flags);
        this.txFreqLmda = U32.normalize(txFreqLmda);
        this.txOffset = U32.normalize(txOffset);
        this.txGridSpan = U32.normalize(txGridSpan);
        this.rxFreqLmda = U32.normalize(rxFreqLmda);
        this.rxOffset = U32.normalize(rxOffset);
        this.rxGridSpan = U32.normalize(rxGridSpan);
        this.txPwr = U16.normalize(txPwr);
        this.rxPwr = U16.normalize(rxPwr);
        this.biasCurrent = U16.normalize(biasCurrent);
        this.temperature = U16.normalize(temperature);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x1;
    }

    @Override
    public long getFlags() {
        return flags;
    }

    @Override
    public long getTxFreqLmda() {
        return txFreqLmda;
    }

    @Override
    public long getTxOffset() {
        return txOffset;
    }

    @Override
    public long getTxGridSpan() {
        return txGridSpan;
    }

    @Override
    public long getRxFreqLmda() {
        return rxFreqLmda;
    }

    @Override
    public long getRxOffset() {
        return rxOffset;
    }

    @Override
    public long getRxGridSpan() {
        return rxGridSpan;
    }

    @Override
    public int getTxPwr() {
        return txPwr;
    }

    @Override
    public int getRxPwr() {
        return rxPwr;
    }

    @Override
    public int getBiasCurrent() {
        return biasCurrent;
    }

    @Override
    public int getTemperature() {
        return temperature;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFPortStatsPropOptical.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFPortStatsPropOptical.Builder {
        final OFPortStatsPropOpticalVer14 parentMessage;

        // OF message fields
        private boolean flagsSet;
        private long flags;
        private boolean txFreqLmdaSet;
        private long txFreqLmda;
        private boolean txOffsetSet;
        private long txOffset;
        private boolean txGridSpanSet;
        private long txGridSpan;
        private boolean rxFreqLmdaSet;
        private long rxFreqLmda;
        private boolean rxOffsetSet;
        private long rxOffset;
        private boolean rxGridSpanSet;
        private long rxGridSpan;
        private boolean txPwrSet;
        private int txPwr;
        private boolean rxPwrSet;
        private int rxPwr;
        private boolean biasCurrentSet;
        private int biasCurrent;
        private boolean temperatureSet;
        private int temperature;

        BuilderWithParent(OFPortStatsPropOpticalVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x1;
    }

    @Override
    public long getFlags() {
        return flags;
    }

    @Override
    public OFPortStatsPropOptical.Builder setFlags(long flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public long getTxFreqLmda() {
        return txFreqLmda;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTxFreqLmda(long txFreqLmda) {
        this.txFreqLmda = txFreqLmda;
        this.txFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getTxOffset() {
        return txOffset;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTxOffset(long txOffset) {
        this.txOffset = txOffset;
        this.txOffsetSet = true;
        return this;
    }
    @Override
    public long getTxGridSpan() {
        return txGridSpan;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTxGridSpan(long txGridSpan) {
        this.txGridSpan = txGridSpan;
        this.txGridSpanSet = true;
        return this;
    }
    @Override
    public long getRxFreqLmda() {
        return rxFreqLmda;
    }

    @Override
    public OFPortStatsPropOptical.Builder setRxFreqLmda(long rxFreqLmda) {
        this.rxFreqLmda = rxFreqLmda;
        this.rxFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getRxOffset() {
        return rxOffset;
    }

    @Override
    public OFPortStatsPropOptical.Builder setRxOffset(long rxOffset) {
        this.rxOffset = rxOffset;
        this.rxOffsetSet = true;
        return this;
    }
    @Override
    public long getRxGridSpan() {
        return rxGridSpan;
    }

    @Override
    public OFPortStatsPropOptical.Builder setRxGridSpan(long rxGridSpan) {
        this.rxGridSpan = rxGridSpan;
        this.rxGridSpanSet = true;
        return this;
    }
    @Override
    public int getTxPwr() {
        return txPwr;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTxPwr(int txPwr) {
        this.txPwr = txPwr;
        this.txPwrSet = true;
        return this;
    }
    @Override
    public int getRxPwr() {
        return rxPwr;
    }

    @Override
    public OFPortStatsPropOptical.Builder setRxPwr(int rxPwr) {
        this.rxPwr = rxPwr;
        this.rxPwrSet = true;
        return this;
    }
    @Override
    public int getBiasCurrent() {
        return biasCurrent;
    }

    @Override
    public OFPortStatsPropOptical.Builder setBiasCurrent(int biasCurrent) {
        this.biasCurrent = biasCurrent;
        this.biasCurrentSet = true;
        return this;
    }
    @Override
    public int getTemperature() {
        return temperature;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTemperature(int temperature) {
        this.temperature = temperature;
        this.temperatureSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFPortStatsPropOptical build() {
                long flags = this.flagsSet ? this.flags : parentMessage.flags;
                long txFreqLmda = this.txFreqLmdaSet ? this.txFreqLmda : parentMessage.txFreqLmda;
                long txOffset = this.txOffsetSet ? this.txOffset : parentMessage.txOffset;
                long txGridSpan = this.txGridSpanSet ? this.txGridSpan : parentMessage.txGridSpan;
                long rxFreqLmda = this.rxFreqLmdaSet ? this.rxFreqLmda : parentMessage.rxFreqLmda;
                long rxOffset = this.rxOffsetSet ? this.rxOffset : parentMessage.rxOffset;
                long rxGridSpan = this.rxGridSpanSet ? this.rxGridSpan : parentMessage.rxGridSpan;
                int txPwr = this.txPwrSet ? this.txPwr : parentMessage.txPwr;
                int rxPwr = this.rxPwrSet ? this.rxPwr : parentMessage.rxPwr;
                int biasCurrent = this.biasCurrentSet ? this.biasCurrent : parentMessage.biasCurrent;
                int temperature = this.temperatureSet ? this.temperature : parentMessage.temperature;

                //
                return new OFPortStatsPropOpticalVer14(
                    flags,
                    txFreqLmda,
                    txOffset,
                    txGridSpan,
                    rxFreqLmda,
                    rxOffset,
                    rxGridSpan,
                    txPwr,
                    rxPwr,
                    biasCurrent,
                    temperature
                );
        }

    }

    static class Builder implements OFPortStatsPropOptical.Builder {
        // OF message fields
        private boolean flagsSet;
        private long flags;
        private boolean txFreqLmdaSet;
        private long txFreqLmda;
        private boolean txOffsetSet;
        private long txOffset;
        private boolean txGridSpanSet;
        private long txGridSpan;
        private boolean rxFreqLmdaSet;
        private long rxFreqLmda;
        private boolean rxOffsetSet;
        private long rxOffset;
        private boolean rxGridSpanSet;
        private long rxGridSpan;
        private boolean txPwrSet;
        private int txPwr;
        private boolean rxPwrSet;
        private int rxPwr;
        private boolean biasCurrentSet;
        private int biasCurrent;
        private boolean temperatureSet;
        private int temperature;

    @Override
    public int getType() {
        return 0x1;
    }

    @Override
    public long getFlags() {
        return flags;
    }

    @Override
    public OFPortStatsPropOptical.Builder setFlags(long flags) {
        this.flags = flags;
        this.flagsSet = true;
        return this;
    }
    @Override
    public long getTxFreqLmda() {
        return txFreqLmda;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTxFreqLmda(long txFreqLmda) {
        this.txFreqLmda = txFreqLmda;
        this.txFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getTxOffset() {
        return txOffset;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTxOffset(long txOffset) {
        this.txOffset = txOffset;
        this.txOffsetSet = true;
        return this;
    }
    @Override
    public long getTxGridSpan() {
        return txGridSpan;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTxGridSpan(long txGridSpan) {
        this.txGridSpan = txGridSpan;
        this.txGridSpanSet = true;
        return this;
    }
    @Override
    public long getRxFreqLmda() {
        return rxFreqLmda;
    }

    @Override
    public OFPortStatsPropOptical.Builder setRxFreqLmda(long rxFreqLmda) {
        this.rxFreqLmda = rxFreqLmda;
        this.rxFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getRxOffset() {
        return rxOffset;
    }

    @Override
    public OFPortStatsPropOptical.Builder setRxOffset(long rxOffset) {
        this.rxOffset = rxOffset;
        this.rxOffsetSet = true;
        return this;
    }
    @Override
    public long getRxGridSpan() {
        return rxGridSpan;
    }

    @Override
    public OFPortStatsPropOptical.Builder setRxGridSpan(long rxGridSpan) {
        this.rxGridSpan = rxGridSpan;
        this.rxGridSpanSet = true;
        return this;
    }
    @Override
    public int getTxPwr() {
        return txPwr;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTxPwr(int txPwr) {
        this.txPwr = txPwr;
        this.txPwrSet = true;
        return this;
    }
    @Override
    public int getRxPwr() {
        return rxPwr;
    }

    @Override
    public OFPortStatsPropOptical.Builder setRxPwr(int rxPwr) {
        this.rxPwr = rxPwr;
        this.rxPwrSet = true;
        return this;
    }
    @Override
    public int getBiasCurrent() {
        return biasCurrent;
    }

    @Override
    public OFPortStatsPropOptical.Builder setBiasCurrent(int biasCurrent) {
        this.biasCurrent = biasCurrent;
        this.biasCurrentSet = true;
        return this;
    }
    @Override
    public int getTemperature() {
        return temperature;
    }

    @Override
    public OFPortStatsPropOptical.Builder setTemperature(int temperature) {
        this.temperature = temperature;
        this.temperatureSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFPortStatsPropOptical build() {
            long flags = this.flagsSet ? this.flags : DEFAULT_FLAGS;
            long txFreqLmda = this.txFreqLmdaSet ? this.txFreqLmda : DEFAULT_TX_FREQ_LMDA;
            long txOffset = this.txOffsetSet ? this.txOffset : DEFAULT_TX_OFFSET;
            long txGridSpan = this.txGridSpanSet ? this.txGridSpan : DEFAULT_TX_GRID_SPAN;
            long rxFreqLmda = this.rxFreqLmdaSet ? this.rxFreqLmda : DEFAULT_RX_FREQ_LMDA;
            long rxOffset = this.rxOffsetSet ? this.rxOffset : DEFAULT_RX_OFFSET;
            long rxGridSpan = this.rxGridSpanSet ? this.rxGridSpan : DEFAULT_RX_GRID_SPAN;
            int txPwr = this.txPwrSet ? this.txPwr : DEFAULT_TX_PWR;
            int rxPwr = this.rxPwrSet ? this.rxPwr : DEFAULT_RX_PWR;
            int biasCurrent = this.biasCurrentSet ? this.biasCurrent : DEFAULT_BIAS_CURRENT;
            int temperature = this.temperatureSet ? this.temperature : DEFAULT_TEMPERATURE;


            return new OFPortStatsPropOpticalVer14(
                    flags,
                    txFreqLmda,
                    txOffset,
                    txGridSpan,
                    rxFreqLmda,
                    rxOffset,
                    rxGridSpan,
                    txPwr,
                    rxPwr,
                    biasCurrent,
                    temperature
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFPortStatsPropOptical> {
        @Override
        public OFPortStatsPropOptical readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x1
            short type = bb.readShort();
            if(type != (short) 0x1)
                throw new OFParseError("Wrong type: Expected=0x1(0x1), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 44)
                throw new OFParseError("Wrong length: Expected=44(44), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            // pad: 4 bytes
            bb.skipBytes(4);
            long flags = U32.f(bb.readInt());
            long txFreqLmda = U32.f(bb.readInt());
            long txOffset = U32.f(bb.readInt());
            long txGridSpan = U32.f(bb.readInt());
            long rxFreqLmda = U32.f(bb.readInt());
            long rxOffset = U32.f(bb.readInt());
            long rxGridSpan = U32.f(bb.readInt());
            int txPwr = U16.f(bb.readShort());
            int rxPwr = U16.f(bb.readShort());
            int biasCurrent = U16.f(bb.readShort());
            int temperature = U16.f(bb.readShort());

            OFPortStatsPropOpticalVer14 portStatsPropOpticalVer14 = new OFPortStatsPropOpticalVer14(
                    flags,
                      txFreqLmda,
                      txOffset,
                      txGridSpan,
                      rxFreqLmda,
                      rxOffset,
                      rxGridSpan,
                      txPwr,
                      rxPwr,
                      biasCurrent,
                      temperature
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", portStatsPropOpticalVer14);
            return portStatsPropOpticalVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFPortStatsPropOpticalVer14Funnel FUNNEL = new OFPortStatsPropOpticalVer14Funnel();
    static class OFPortStatsPropOpticalVer14Funnel implements Funnel<OFPortStatsPropOpticalVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFPortStatsPropOpticalVer14 message, PrimitiveSink sink) {
            // fixed value property type = 0x1
            sink.putShort((short) 0x1);
            // fixed value property length = 44
            sink.putShort((short) 0x2c);
            // skip pad (4 bytes)
            sink.putLong(message.flags);
            sink.putLong(message.txFreqLmda);
            sink.putLong(message.txOffset);
            sink.putLong(message.txGridSpan);
            sink.putLong(message.rxFreqLmda);
            sink.putLong(message.rxOffset);
            sink.putLong(message.rxGridSpan);
            sink.putInt(message.txPwr);
            sink.putInt(message.rxPwr);
            sink.putInt(message.biasCurrent);
            sink.putInt(message.temperature);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFPortStatsPropOpticalVer14> {
        @Override
        public void write(ByteBuf bb, OFPortStatsPropOpticalVer14 message) {
            // fixed value property type = 0x1
            bb.writeShort((short) 0x1);
            // fixed value property length = 44
            bb.writeShort((short) 0x2c);
            // pad: 4 bytes
            bb.writeZero(4);
            bb.writeInt(U32.t(message.flags));
            bb.writeInt(U32.t(message.txFreqLmda));
            bb.writeInt(U32.t(message.txOffset));
            bb.writeInt(U32.t(message.txGridSpan));
            bb.writeInt(U32.t(message.rxFreqLmda));
            bb.writeInt(U32.t(message.rxOffset));
            bb.writeInt(U32.t(message.rxGridSpan));
            bb.writeShort(U16.t(message.txPwr));
            bb.writeShort(U16.t(message.rxPwr));
            bb.writeShort(U16.t(message.biasCurrent));
            bb.writeShort(U16.t(message.temperature));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFPortStatsPropOpticalVer14(");
        b.append("flags=").append(flags);
        b.append(", ");
        b.append("txFreqLmda=").append(txFreqLmda);
        b.append(", ");
        b.append("txOffset=").append(txOffset);
        b.append(", ");
        b.append("txGridSpan=").append(txGridSpan);
        b.append(", ");
        b.append("rxFreqLmda=").append(rxFreqLmda);
        b.append(", ");
        b.append("rxOffset=").append(rxOffset);
        b.append(", ");
        b.append("rxGridSpan=").append(rxGridSpan);
        b.append(", ");
        b.append("txPwr=").append(txPwr);
        b.append(", ");
        b.append("rxPwr=").append(rxPwr);
        b.append(", ");
        b.append("biasCurrent=").append(biasCurrent);
        b.append(", ");
        b.append("temperature=").append(temperature);
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
        OFPortStatsPropOpticalVer14 other = (OFPortStatsPropOpticalVer14) obj;

        if( flags != other.flags)
            return false;
        if( txFreqLmda != other.txFreqLmda)
            return false;
        if( txOffset != other.txOffset)
            return false;
        if( txGridSpan != other.txGridSpan)
            return false;
        if( rxFreqLmda != other.rxFreqLmda)
            return false;
        if( rxOffset != other.rxOffset)
            return false;
        if( rxGridSpan != other.rxGridSpan)
            return false;
        if( txPwr != other.txPwr)
            return false;
        if( rxPwr != other.rxPwr)
            return false;
        if( biasCurrent != other.biasCurrent)
            return false;
        if( temperature != other.temperature)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (flags ^ (flags >>> 32));
        result = prime *  (int) (txFreqLmda ^ (txFreqLmda >>> 32));
        result = prime *  (int) (txOffset ^ (txOffset >>> 32));
        result = prime *  (int) (txGridSpan ^ (txGridSpan >>> 32));
        result = prime *  (int) (rxFreqLmda ^ (rxFreqLmda >>> 32));
        result = prime *  (int) (rxOffset ^ (rxOffset >>> 32));
        result = prime *  (int) (rxGridSpan ^ (rxGridSpan >>> 32));
        result = prime * result + txPwr;
        result = prime * result + rxPwr;
        result = prime * result + biasCurrent;
        result = prime * result + temperature;
        return result;
    }

}
