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

class OFMeterFeaturesVer14 implements OFMeterFeatures {
    private static final Logger logger = LoggerFactory.getLogger(OFMeterFeaturesVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 16;

        private final static long DEFAULT_MAX_METER = 0x0L;
        private final static long DEFAULT_BAND_TYPES = 0x0L;
        private final static long DEFAULT_CAPABILITIES = 0x0L;
        private final static short DEFAULT_MAX_BANDS = (short) 0x0;
        private final static short DEFAULT_MAX_COLOR = (short) 0x0;

    // OF message fields
    private final long maxMeter;
    private final long bandTypes;
    private final long capabilities;
    private final short maxBands;
    private final short maxColor;
//
    // Immutable default instance
    final static OFMeterFeaturesVer14 DEFAULT = new OFMeterFeaturesVer14(
        DEFAULT_MAX_METER, DEFAULT_BAND_TYPES, DEFAULT_CAPABILITIES, DEFAULT_MAX_BANDS, DEFAULT_MAX_COLOR
    );

    // package private constructor - used by readers, builders, and factory
    OFMeterFeaturesVer14(long maxMeter, long bandTypes, long capabilities, short maxBands, short maxColor) {
        this.maxMeter = U32.normalize(maxMeter);
        this.bandTypes = U32.normalize(bandTypes);
        this.capabilities = U32.normalize(capabilities);
        this.maxBands = U8.normalize(maxBands);
        this.maxColor = U8.normalize(maxColor);
    }

    // Accessors for OF message fields
    @Override
    public long getMaxMeter() {
        return maxMeter;
    }

    @Override
    public long getBandTypes() {
        return bandTypes;
    }

    @Override
    public long getCapabilities() {
        return capabilities;
    }

    @Override
    public short getMaxBands() {
        return maxBands;
    }

    @Override
    public short getMaxColor() {
        return maxColor;
    }

    @Override
    public long getFeatures()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property features not supported in version 1.4");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFMeterFeatures.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFMeterFeatures.Builder {
        final OFMeterFeaturesVer14 parentMessage;

        // OF message fields
        private boolean maxMeterSet;
        private long maxMeter;
        private boolean bandTypesSet;
        private long bandTypes;
        private boolean capabilitiesSet;
        private long capabilities;
        private boolean maxBandsSet;
        private short maxBands;
        private boolean maxColorSet;
        private short maxColor;

        BuilderWithParent(OFMeterFeaturesVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public long getMaxMeter() {
        return maxMeter;
    }

    @Override
    public OFMeterFeatures.Builder setMaxMeter(long maxMeter) {
        this.maxMeter = maxMeter;
        this.maxMeterSet = true;
        return this;
    }
    @Override
    public long getBandTypes() {
        return bandTypes;
    }

    @Override
    public OFMeterFeatures.Builder setBandTypes(long bandTypes) {
        this.bandTypes = bandTypes;
        this.bandTypesSet = true;
        return this;
    }
    @Override
    public long getCapabilities() {
        return capabilities;
    }

    @Override
    public OFMeterFeatures.Builder setCapabilities(long capabilities) {
        this.capabilities = capabilities;
        this.capabilitiesSet = true;
        return this;
    }
    @Override
    public short getMaxBands() {
        return maxBands;
    }

    @Override
    public OFMeterFeatures.Builder setMaxBands(short maxBands) {
        this.maxBands = maxBands;
        this.maxBandsSet = true;
        return this;
    }
    @Override
    public short getMaxColor() {
        return maxColor;
    }

    @Override
    public OFMeterFeatures.Builder setMaxColor(short maxColor) {
        this.maxColor = maxColor;
        this.maxColorSet = true;
        return this;
    }
    @Override
    public long getFeatures()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property features not supported in version 1.4");
    }

    @Override
    public OFMeterFeatures.Builder setFeatures(long features) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property features not supported in version 1.4");
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFMeterFeatures build() {
                long maxMeter = this.maxMeterSet ? this.maxMeter : parentMessage.maxMeter;
                long bandTypes = this.bandTypesSet ? this.bandTypes : parentMessage.bandTypes;
                long capabilities = this.capabilitiesSet ? this.capabilities : parentMessage.capabilities;
                short maxBands = this.maxBandsSet ? this.maxBands : parentMessage.maxBands;
                short maxColor = this.maxColorSet ? this.maxColor : parentMessage.maxColor;

                //
                return new OFMeterFeaturesVer14(
                    maxMeter,
                    bandTypes,
                    capabilities,
                    maxBands,
                    maxColor
                );
        }

    }

    static class Builder implements OFMeterFeatures.Builder {
        // OF message fields
        private boolean maxMeterSet;
        private long maxMeter;
        private boolean bandTypesSet;
        private long bandTypes;
        private boolean capabilitiesSet;
        private long capabilities;
        private boolean maxBandsSet;
        private short maxBands;
        private boolean maxColorSet;
        private short maxColor;

    @Override
    public long getMaxMeter() {
        return maxMeter;
    }

    @Override
    public OFMeterFeatures.Builder setMaxMeter(long maxMeter) {
        this.maxMeter = maxMeter;
        this.maxMeterSet = true;
        return this;
    }
    @Override
    public long getBandTypes() {
        return bandTypes;
    }

    @Override
    public OFMeterFeatures.Builder setBandTypes(long bandTypes) {
        this.bandTypes = bandTypes;
        this.bandTypesSet = true;
        return this;
    }
    @Override
    public long getCapabilities() {
        return capabilities;
    }

    @Override
    public OFMeterFeatures.Builder setCapabilities(long capabilities) {
        this.capabilities = capabilities;
        this.capabilitiesSet = true;
        return this;
    }
    @Override
    public short getMaxBands() {
        return maxBands;
    }

    @Override
    public OFMeterFeatures.Builder setMaxBands(short maxBands) {
        this.maxBands = maxBands;
        this.maxBandsSet = true;
        return this;
    }
    @Override
    public short getMaxColor() {
        return maxColor;
    }

    @Override
    public OFMeterFeatures.Builder setMaxColor(short maxColor) {
        this.maxColor = maxColor;
        this.maxColorSet = true;
        return this;
    }
    @Override
    public long getFeatures()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property features not supported in version 1.4");
    }

    @Override
    public OFMeterFeatures.Builder setFeatures(long features) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property features not supported in version 1.4");
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFMeterFeatures build() {
            long maxMeter = this.maxMeterSet ? this.maxMeter : DEFAULT_MAX_METER;
            long bandTypes = this.bandTypesSet ? this.bandTypes : DEFAULT_BAND_TYPES;
            long capabilities = this.capabilitiesSet ? this.capabilities : DEFAULT_CAPABILITIES;
            short maxBands = this.maxBandsSet ? this.maxBands : DEFAULT_MAX_BANDS;
            short maxColor = this.maxColorSet ? this.maxColor : DEFAULT_MAX_COLOR;


            return new OFMeterFeaturesVer14(
                    maxMeter,
                    bandTypes,
                    capabilities,
                    maxBands,
                    maxColor
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFMeterFeatures> {
        @Override
        public OFMeterFeatures readFrom(ByteBuf bb) throws OFParseError {
            long maxMeter = U32.f(bb.readInt());
            long bandTypes = U32.f(bb.readInt());
            long capabilities = U32.f(bb.readInt());
            short maxBands = U8.f(bb.readByte());
            short maxColor = U8.f(bb.readByte());
            // pad: 2 bytes
            bb.skipBytes(2);

            OFMeterFeaturesVer14 meterFeaturesVer14 = new OFMeterFeaturesVer14(
                    maxMeter,
                      bandTypes,
                      capabilities,
                      maxBands,
                      maxColor
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", meterFeaturesVer14);
            return meterFeaturesVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFMeterFeaturesVer14Funnel FUNNEL = new OFMeterFeaturesVer14Funnel();
    static class OFMeterFeaturesVer14Funnel implements Funnel<OFMeterFeaturesVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFMeterFeaturesVer14 message, PrimitiveSink sink) {
            sink.putLong(message.maxMeter);
            sink.putLong(message.bandTypes);
            sink.putLong(message.capabilities);
            sink.putShort(message.maxBands);
            sink.putShort(message.maxColor);
            // skip pad (2 bytes)
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFMeterFeaturesVer14> {
        @Override
        public void write(ByteBuf bb, OFMeterFeaturesVer14 message) {
            bb.writeInt(U32.t(message.maxMeter));
            bb.writeInt(U32.t(message.bandTypes));
            bb.writeInt(U32.t(message.capabilities));
            bb.writeByte(U8.t(message.maxBands));
            bb.writeByte(U8.t(message.maxColor));
            // pad: 2 bytes
            bb.writeZero(2);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFMeterFeaturesVer14(");
        b.append("maxMeter=").append(maxMeter);
        b.append(", ");
        b.append("bandTypes=").append(bandTypes);
        b.append(", ");
        b.append("capabilities=").append(capabilities);
        b.append(", ");
        b.append("maxBands=").append(maxBands);
        b.append(", ");
        b.append("maxColor=").append(maxColor);
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
        OFMeterFeaturesVer14 other = (OFMeterFeaturesVer14) obj;

        if( maxMeter != other.maxMeter)
            return false;
        if( bandTypes != other.bandTypes)
            return false;
        if( capabilities != other.capabilities)
            return false;
        if( maxBands != other.maxBands)
            return false;
        if( maxColor != other.maxColor)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (maxMeter ^ (maxMeter >>> 32));
        result = prime *  (int) (bandTypes ^ (bandTypes >>> 32));
        result = prime *  (int) (capabilities ^ (capabilities >>> 32));
        result = prime * result + maxBands;
        result = prime * result + maxColor;
        return result;
    }

}
