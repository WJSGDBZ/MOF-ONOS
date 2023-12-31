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

class OFPortDescPropOpticalVer14 implements OFPortDescPropOptical {
    private static final Logger logger = LoggerFactory.getLogger(OFPortDescPropOpticalVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 44;

        private final static long DEFAULT_SUPPORTED = 0x0L;
        private final static long DEFAULT_TX_MIN_FREQ_LMDA = 0x0L;
        private final static long DEFAULT_TX_MAX_FREQ_LMDA = 0x0L;
        private final static long DEFAULT_TX_GRID_FREQ_LMDA = 0x0L;
        private final static long DEFAULT_RX_MIN_FREQ_LMDA = 0x0L;
        private final static long DEFAULT_RX_MAX_FREQ_LMDA = 0x0L;
        private final static long DEFAULT_RX_GRID_FREQ_LMDA = 0x0L;
        private final static long DEFAULT_TX_PWR_MIN = 0x0L;
        private final static long DEFAULT_TX_PWR_MAX = 0x0L;

    // OF message fields
    private final long supported;
    private final long txMinFreqLmda;
    private final long txMaxFreqLmda;
    private final long txGridFreqLmda;
    private final long rxMinFreqLmda;
    private final long rxMaxFreqLmda;
    private final long rxGridFreqLmda;
    private final long txPwrMin;
    private final long txPwrMax;
//
    // Immutable default instance
    final static OFPortDescPropOpticalVer14 DEFAULT = new OFPortDescPropOpticalVer14(
        DEFAULT_SUPPORTED, DEFAULT_TX_MIN_FREQ_LMDA, DEFAULT_TX_MAX_FREQ_LMDA, DEFAULT_TX_GRID_FREQ_LMDA, DEFAULT_RX_MIN_FREQ_LMDA, DEFAULT_RX_MAX_FREQ_LMDA, DEFAULT_RX_GRID_FREQ_LMDA, DEFAULT_TX_PWR_MIN, DEFAULT_TX_PWR_MAX
    );

    // package private constructor - used by readers, builders, and factory
    OFPortDescPropOpticalVer14(long supported, long txMinFreqLmda, long txMaxFreqLmda, long txGridFreqLmda, long rxMinFreqLmda, long rxMaxFreqLmda, long rxGridFreqLmda, long txPwrMin, long txPwrMax) {
        this.supported = U32.normalize(supported);
        this.txMinFreqLmda = U32.normalize(txMinFreqLmda);
        this.txMaxFreqLmda = U32.normalize(txMaxFreqLmda);
        this.txGridFreqLmda = U32.normalize(txGridFreqLmda);
        this.rxMinFreqLmda = U32.normalize(rxMinFreqLmda);
        this.rxMaxFreqLmda = U32.normalize(rxMaxFreqLmda);
        this.rxGridFreqLmda = U32.normalize(rxGridFreqLmda);
        this.txPwrMin = U32.normalize(txPwrMin);
        this.txPwrMax = U32.normalize(txPwrMax);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x1;
    }

    @Override
    public long getSupported() {
        return supported;
    }

    @Override
    public long getTxMinFreqLmda() {
        return txMinFreqLmda;
    }

    @Override
    public long getTxMaxFreqLmda() {
        return txMaxFreqLmda;
    }

    @Override
    public long getTxGridFreqLmda() {
        return txGridFreqLmda;
    }

    @Override
    public long getRxMinFreqLmda() {
        return rxMinFreqLmda;
    }

    @Override
    public long getRxMaxFreqLmda() {
        return rxMaxFreqLmda;
    }

    @Override
    public long getRxGridFreqLmda() {
        return rxGridFreqLmda;
    }

    @Override
    public long getTxPwrMin() {
        return txPwrMin;
    }

    @Override
    public long getTxPwrMax() {
        return txPwrMax;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFPortDescPropOptical.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFPortDescPropOptical.Builder {
        final OFPortDescPropOpticalVer14 parentMessage;

        // OF message fields
        private boolean supportedSet;
        private long supported;
        private boolean txMinFreqLmdaSet;
        private long txMinFreqLmda;
        private boolean txMaxFreqLmdaSet;
        private long txMaxFreqLmda;
        private boolean txGridFreqLmdaSet;
        private long txGridFreqLmda;
        private boolean rxMinFreqLmdaSet;
        private long rxMinFreqLmda;
        private boolean rxMaxFreqLmdaSet;
        private long rxMaxFreqLmda;
        private boolean rxGridFreqLmdaSet;
        private long rxGridFreqLmda;
        private boolean txPwrMinSet;
        private long txPwrMin;
        private boolean txPwrMaxSet;
        private long txPwrMax;

        BuilderWithParent(OFPortDescPropOpticalVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x1;
    }

    @Override
    public long getSupported() {
        return supported;
    }

    @Override
    public OFPortDescPropOptical.Builder setSupported(long supported) {
        this.supported = supported;
        this.supportedSet = true;
        return this;
    }
    @Override
    public long getTxMinFreqLmda() {
        return txMinFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxMinFreqLmda(long txMinFreqLmda) {
        this.txMinFreqLmda = txMinFreqLmda;
        this.txMinFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getTxMaxFreqLmda() {
        return txMaxFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxMaxFreqLmda(long txMaxFreqLmda) {
        this.txMaxFreqLmda = txMaxFreqLmda;
        this.txMaxFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getTxGridFreqLmda() {
        return txGridFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxGridFreqLmda(long txGridFreqLmda) {
        this.txGridFreqLmda = txGridFreqLmda;
        this.txGridFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getRxMinFreqLmda() {
        return rxMinFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setRxMinFreqLmda(long rxMinFreqLmda) {
        this.rxMinFreqLmda = rxMinFreqLmda;
        this.rxMinFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getRxMaxFreqLmda() {
        return rxMaxFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setRxMaxFreqLmda(long rxMaxFreqLmda) {
        this.rxMaxFreqLmda = rxMaxFreqLmda;
        this.rxMaxFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getRxGridFreqLmda() {
        return rxGridFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setRxGridFreqLmda(long rxGridFreqLmda) {
        this.rxGridFreqLmda = rxGridFreqLmda;
        this.rxGridFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getTxPwrMin() {
        return txPwrMin;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxPwrMin(long txPwrMin) {
        this.txPwrMin = txPwrMin;
        this.txPwrMinSet = true;
        return this;
    }
    @Override
    public long getTxPwrMax() {
        return txPwrMax;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxPwrMax(long txPwrMax) {
        this.txPwrMax = txPwrMax;
        this.txPwrMaxSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFPortDescPropOptical build() {
                long supported = this.supportedSet ? this.supported : parentMessage.supported;
                long txMinFreqLmda = this.txMinFreqLmdaSet ? this.txMinFreqLmda : parentMessage.txMinFreqLmda;
                long txMaxFreqLmda = this.txMaxFreqLmdaSet ? this.txMaxFreqLmda : parentMessage.txMaxFreqLmda;
                long txGridFreqLmda = this.txGridFreqLmdaSet ? this.txGridFreqLmda : parentMessage.txGridFreqLmda;
                long rxMinFreqLmda = this.rxMinFreqLmdaSet ? this.rxMinFreqLmda : parentMessage.rxMinFreqLmda;
                long rxMaxFreqLmda = this.rxMaxFreqLmdaSet ? this.rxMaxFreqLmda : parentMessage.rxMaxFreqLmda;
                long rxGridFreqLmda = this.rxGridFreqLmdaSet ? this.rxGridFreqLmda : parentMessage.rxGridFreqLmda;
                long txPwrMin = this.txPwrMinSet ? this.txPwrMin : parentMessage.txPwrMin;
                long txPwrMax = this.txPwrMaxSet ? this.txPwrMax : parentMessage.txPwrMax;

                //
                return new OFPortDescPropOpticalVer14(
                    supported,
                    txMinFreqLmda,
                    txMaxFreqLmda,
                    txGridFreqLmda,
                    rxMinFreqLmda,
                    rxMaxFreqLmda,
                    rxGridFreqLmda,
                    txPwrMin,
                    txPwrMax
                );
        }

    }

    static class Builder implements OFPortDescPropOptical.Builder {
        // OF message fields
        private boolean supportedSet;
        private long supported;
        private boolean txMinFreqLmdaSet;
        private long txMinFreqLmda;
        private boolean txMaxFreqLmdaSet;
        private long txMaxFreqLmda;
        private boolean txGridFreqLmdaSet;
        private long txGridFreqLmda;
        private boolean rxMinFreqLmdaSet;
        private long rxMinFreqLmda;
        private boolean rxMaxFreqLmdaSet;
        private long rxMaxFreqLmda;
        private boolean rxGridFreqLmdaSet;
        private long rxGridFreqLmda;
        private boolean txPwrMinSet;
        private long txPwrMin;
        private boolean txPwrMaxSet;
        private long txPwrMax;

    @Override
    public int getType() {
        return 0x1;
    }

    @Override
    public long getSupported() {
        return supported;
    }

    @Override
    public OFPortDescPropOptical.Builder setSupported(long supported) {
        this.supported = supported;
        this.supportedSet = true;
        return this;
    }
    @Override
    public long getTxMinFreqLmda() {
        return txMinFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxMinFreqLmda(long txMinFreqLmda) {
        this.txMinFreqLmda = txMinFreqLmda;
        this.txMinFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getTxMaxFreqLmda() {
        return txMaxFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxMaxFreqLmda(long txMaxFreqLmda) {
        this.txMaxFreqLmda = txMaxFreqLmda;
        this.txMaxFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getTxGridFreqLmda() {
        return txGridFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxGridFreqLmda(long txGridFreqLmda) {
        this.txGridFreqLmda = txGridFreqLmda;
        this.txGridFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getRxMinFreqLmda() {
        return rxMinFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setRxMinFreqLmda(long rxMinFreqLmda) {
        this.rxMinFreqLmda = rxMinFreqLmda;
        this.rxMinFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getRxMaxFreqLmda() {
        return rxMaxFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setRxMaxFreqLmda(long rxMaxFreqLmda) {
        this.rxMaxFreqLmda = rxMaxFreqLmda;
        this.rxMaxFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getRxGridFreqLmda() {
        return rxGridFreqLmda;
    }

    @Override
    public OFPortDescPropOptical.Builder setRxGridFreqLmda(long rxGridFreqLmda) {
        this.rxGridFreqLmda = rxGridFreqLmda;
        this.rxGridFreqLmdaSet = true;
        return this;
    }
    @Override
    public long getTxPwrMin() {
        return txPwrMin;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxPwrMin(long txPwrMin) {
        this.txPwrMin = txPwrMin;
        this.txPwrMinSet = true;
        return this;
    }
    @Override
    public long getTxPwrMax() {
        return txPwrMax;
    }

    @Override
    public OFPortDescPropOptical.Builder setTxPwrMax(long txPwrMax) {
        this.txPwrMax = txPwrMax;
        this.txPwrMaxSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFPortDescPropOptical build() {
            long supported = this.supportedSet ? this.supported : DEFAULT_SUPPORTED;
            long txMinFreqLmda = this.txMinFreqLmdaSet ? this.txMinFreqLmda : DEFAULT_TX_MIN_FREQ_LMDA;
            long txMaxFreqLmda = this.txMaxFreqLmdaSet ? this.txMaxFreqLmda : DEFAULT_TX_MAX_FREQ_LMDA;
            long txGridFreqLmda = this.txGridFreqLmdaSet ? this.txGridFreqLmda : DEFAULT_TX_GRID_FREQ_LMDA;
            long rxMinFreqLmda = this.rxMinFreqLmdaSet ? this.rxMinFreqLmda : DEFAULT_RX_MIN_FREQ_LMDA;
            long rxMaxFreqLmda = this.rxMaxFreqLmdaSet ? this.rxMaxFreqLmda : DEFAULT_RX_MAX_FREQ_LMDA;
            long rxGridFreqLmda = this.rxGridFreqLmdaSet ? this.rxGridFreqLmda : DEFAULT_RX_GRID_FREQ_LMDA;
            long txPwrMin = this.txPwrMinSet ? this.txPwrMin : DEFAULT_TX_PWR_MIN;
            long txPwrMax = this.txPwrMaxSet ? this.txPwrMax : DEFAULT_TX_PWR_MAX;


            return new OFPortDescPropOpticalVer14(
                    supported,
                    txMinFreqLmda,
                    txMaxFreqLmda,
                    txGridFreqLmda,
                    rxMinFreqLmda,
                    rxMaxFreqLmda,
                    rxGridFreqLmda,
                    txPwrMin,
                    txPwrMax
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFPortDescPropOptical> {
        @Override
        public OFPortDescPropOptical readFrom(ByteBuf bb) throws OFParseError {
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
            long supported = U32.f(bb.readInt());
            long txMinFreqLmda = U32.f(bb.readInt());
            long txMaxFreqLmda = U32.f(bb.readInt());
            long txGridFreqLmda = U32.f(bb.readInt());
            long rxMinFreqLmda = U32.f(bb.readInt());
            long rxMaxFreqLmda = U32.f(bb.readInt());
            long rxGridFreqLmda = U32.f(bb.readInt());
            long txPwrMin = U32.f(bb.readInt());
            long txPwrMax = U32.f(bb.readInt());

            OFPortDescPropOpticalVer14 portDescPropOpticalVer14 = new OFPortDescPropOpticalVer14(
                    supported,
                      txMinFreqLmda,
                      txMaxFreqLmda,
                      txGridFreqLmda,
                      rxMinFreqLmda,
                      rxMaxFreqLmda,
                      rxGridFreqLmda,
                      txPwrMin,
                      txPwrMax
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", portDescPropOpticalVer14);
            return portDescPropOpticalVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFPortDescPropOpticalVer14Funnel FUNNEL = new OFPortDescPropOpticalVer14Funnel();
    static class OFPortDescPropOpticalVer14Funnel implements Funnel<OFPortDescPropOpticalVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFPortDescPropOpticalVer14 message, PrimitiveSink sink) {
            // fixed value property type = 0x1
            sink.putShort((short) 0x1);
            // fixed value property length = 44
            sink.putShort((short) 0x2c);
            // skip pad (4 bytes)
            sink.putLong(message.supported);
            sink.putLong(message.txMinFreqLmda);
            sink.putLong(message.txMaxFreqLmda);
            sink.putLong(message.txGridFreqLmda);
            sink.putLong(message.rxMinFreqLmda);
            sink.putLong(message.rxMaxFreqLmda);
            sink.putLong(message.rxGridFreqLmda);
            sink.putLong(message.txPwrMin);
            sink.putLong(message.txPwrMax);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFPortDescPropOpticalVer14> {
        @Override
        public void write(ByteBuf bb, OFPortDescPropOpticalVer14 message) {
            // fixed value property type = 0x1
            bb.writeShort((short) 0x1);
            // fixed value property length = 44
            bb.writeShort((short) 0x2c);
            // pad: 4 bytes
            bb.writeZero(4);
            bb.writeInt(U32.t(message.supported));
            bb.writeInt(U32.t(message.txMinFreqLmda));
            bb.writeInt(U32.t(message.txMaxFreqLmda));
            bb.writeInt(U32.t(message.txGridFreqLmda));
            bb.writeInt(U32.t(message.rxMinFreqLmda));
            bb.writeInt(U32.t(message.rxMaxFreqLmda));
            bb.writeInt(U32.t(message.rxGridFreqLmda));
            bb.writeInt(U32.t(message.txPwrMin));
            bb.writeInt(U32.t(message.txPwrMax));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFPortDescPropOpticalVer14(");
        b.append("supported=").append(supported);
        b.append(", ");
        b.append("txMinFreqLmda=").append(txMinFreqLmda);
        b.append(", ");
        b.append("txMaxFreqLmda=").append(txMaxFreqLmda);
        b.append(", ");
        b.append("txGridFreqLmda=").append(txGridFreqLmda);
        b.append(", ");
        b.append("rxMinFreqLmda=").append(rxMinFreqLmda);
        b.append(", ");
        b.append("rxMaxFreqLmda=").append(rxMaxFreqLmda);
        b.append(", ");
        b.append("rxGridFreqLmda=").append(rxGridFreqLmda);
        b.append(", ");
        b.append("txPwrMin=").append(txPwrMin);
        b.append(", ");
        b.append("txPwrMax=").append(txPwrMax);
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
        OFPortDescPropOpticalVer14 other = (OFPortDescPropOpticalVer14) obj;

        if( supported != other.supported)
            return false;
        if( txMinFreqLmda != other.txMinFreqLmda)
            return false;
        if( txMaxFreqLmda != other.txMaxFreqLmda)
            return false;
        if( txGridFreqLmda != other.txGridFreqLmda)
            return false;
        if( rxMinFreqLmda != other.rxMinFreqLmda)
            return false;
        if( rxMaxFreqLmda != other.rxMaxFreqLmda)
            return false;
        if( rxGridFreqLmda != other.rxGridFreqLmda)
            return false;
        if( txPwrMin != other.txPwrMin)
            return false;
        if( txPwrMax != other.txPwrMax)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (supported ^ (supported >>> 32));
        result = prime *  (int) (txMinFreqLmda ^ (txMinFreqLmda >>> 32));
        result = prime *  (int) (txMaxFreqLmda ^ (txMaxFreqLmda >>> 32));
        result = prime *  (int) (txGridFreqLmda ^ (txGridFreqLmda >>> 32));
        result = prime *  (int) (rxMinFreqLmda ^ (rxMinFreqLmda >>> 32));
        result = prime *  (int) (rxMaxFreqLmda ^ (rxMaxFreqLmda >>> 32));
        result = prime *  (int) (rxGridFreqLmda ^ (rxGridFreqLmda >>> 32));
        result = prime *  (int) (txPwrMin ^ (txPwrMin >>> 32));
        result = prime *  (int) (txPwrMax ^ (txPwrMax >>> 32));
        return result;
    }

}
