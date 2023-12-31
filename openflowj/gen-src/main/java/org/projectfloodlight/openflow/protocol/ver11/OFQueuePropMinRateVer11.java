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
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFQueuePropMinRateVer11 implements OFQueuePropMinRate {
    private static final Logger logger = LoggerFactory.getLogger(OFQueuePropMinRateVer11.class);
    // version: 1.1
    final static byte WIRE_VERSION = 2;
    final static int LENGTH = 16;

        private final static int DEFAULT_RATE = 0x0;

    // OF message fields
    private final int rate;
//
    // Immutable default instance
    final static OFQueuePropMinRateVer11 DEFAULT = new OFQueuePropMinRateVer11(
        DEFAULT_RATE
    );

    // package private constructor - used by readers, builders, and factory
    OFQueuePropMinRateVer11(int rate) {
        this.rate = U16.normalize(rate);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x1;
    }

    @Override
    public int getRate() {
        return rate;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }



    public OFQueuePropMinRate.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFQueuePropMinRate.Builder {
        final OFQueuePropMinRateVer11 parentMessage;

        // OF message fields
        private boolean rateSet;
        private int rate;

        BuilderWithParent(OFQueuePropMinRateVer11 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x1;
    }

    @Override
    public int getRate() {
        return rate;
    }

    @Override
    public OFQueuePropMinRate.Builder setRate(int rate) {
        this.rate = rate;
        this.rateSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }



        @Override
        public OFQueuePropMinRate build() {
                int rate = this.rateSet ? this.rate : parentMessage.rate;

                //
                return new OFQueuePropMinRateVer11(
                    rate
                );
        }

    }

    static class Builder implements OFQueuePropMinRate.Builder {
        // OF message fields
        private boolean rateSet;
        private int rate;

    @Override
    public int getType() {
        return 0x1;
    }

    @Override
    public int getRate() {
        return rate;
    }

    @Override
    public OFQueuePropMinRate.Builder setRate(int rate) {
        this.rate = rate;
        this.rateSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_11;
    }

//
        @Override
        public OFQueuePropMinRate build() {
            int rate = this.rateSet ? this.rate : DEFAULT_RATE;


            return new OFQueuePropMinRateVer11(
                    rate
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFQueuePropMinRate> {
        @Override
        public OFQueuePropMinRate readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x1
            short type = bb.readShort();
            if(type != (short) 0x1)
                throw new OFParseError("Wrong type: Expected=0x1(0x1), got="+type);
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
            // pad: 4 bytes
            bb.skipBytes(4);
            int rate = U16.f(bb.readShort());
            // pad: 6 bytes
            bb.skipBytes(6);

            OFQueuePropMinRateVer11 queuePropMinRateVer11 = new OFQueuePropMinRateVer11(
                    rate
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", queuePropMinRateVer11);
            return queuePropMinRateVer11;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFQueuePropMinRateVer11Funnel FUNNEL = new OFQueuePropMinRateVer11Funnel();
    static class OFQueuePropMinRateVer11Funnel implements Funnel<OFQueuePropMinRateVer11> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFQueuePropMinRateVer11 message, PrimitiveSink sink) {
            // fixed value property type = 0x1
            sink.putShort((short) 0x1);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            // skip pad (4 bytes)
            sink.putInt(message.rate);
            // skip pad (6 bytes)
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFQueuePropMinRateVer11> {
        @Override
        public void write(ByteBuf bb, OFQueuePropMinRateVer11 message) {
            // fixed value property type = 0x1
            bb.writeShort((short) 0x1);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            // pad: 4 bytes
            bb.writeZero(4);
            bb.writeShort(U16.t(message.rate));
            // pad: 6 bytes
            bb.writeZero(6);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFQueuePropMinRateVer11(");
        b.append("rate=").append(rate);
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
        OFQueuePropMinRateVer11 other = (OFQueuePropMinRateVer11) obj;

        if( rate != other.rate)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + rate;
        return result;
    }

}
