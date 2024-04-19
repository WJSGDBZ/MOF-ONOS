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
import java.util.List;
import com.google.common.collect.ImmutableList;
import java.util.Set;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFTableFeaturePropWildcardsVer15 implements OFTableFeaturePropWildcards {
    private static final Logger logger = LoggerFactory.getLogger(OFTableFeaturePropWildcardsVer15.class);
    // version: 1.5
    final static byte WIRE_VERSION = 6;
    final static int MINIMUM_LENGTH = 4;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static List<U32> DEFAULT_OXM_IDS = ImmutableList.<U32>of();

    // OF message fields
    private final List<U32> oxmIds;
//
    // Immutable default instance
    final static OFTableFeaturePropWildcardsVer15 DEFAULT = new OFTableFeaturePropWildcardsVer15(
        DEFAULT_OXM_IDS
    );

    // package private constructor - used by readers, builders, and factory
    OFTableFeaturePropWildcardsVer15(List<U32> oxmIds) {
        if(oxmIds == null) {
            throw new NullPointerException("OFTableFeaturePropWildcardsVer15: property oxmIds cannot be null");
        }
        this.oxmIds = oxmIds;
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0xa;
    }

    @Override
    public List<U32> getOxmIds() {
        return oxmIds;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



    public OFTableFeaturePropWildcards.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFTableFeaturePropWildcards.Builder {
        final OFTableFeaturePropWildcardsVer15 parentMessage;

        // OF message fields
        private boolean oxmIdsSet;
        private List<U32> oxmIds;

        BuilderWithParent(OFTableFeaturePropWildcardsVer15 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0xa;
    }

    @Override
    public List<U32> getOxmIds() {
        return oxmIds;
    }

    @Override
    public OFTableFeaturePropWildcards.Builder setOxmIds(List<U32> oxmIds) {
        this.oxmIds = oxmIds;
        this.oxmIdsSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



        @Override
        public OFTableFeaturePropWildcards build() {
                List<U32> oxmIds = this.oxmIdsSet ? this.oxmIds : parentMessage.oxmIds;
                if(oxmIds == null)
                    throw new NullPointerException("Property oxmIds must not be null");

                //
                return new OFTableFeaturePropWildcardsVer15(
                    oxmIds
                );
        }

    }

    static class Builder implements OFTableFeaturePropWildcards.Builder {
        // OF message fields
        private boolean oxmIdsSet;
        private List<U32> oxmIds;

    @Override
    public int getType() {
        return 0xa;
    }

    @Override
    public List<U32> getOxmIds() {
        return oxmIds;
    }

    @Override
    public OFTableFeaturePropWildcards.Builder setOxmIds(List<U32> oxmIds) {
        this.oxmIds = oxmIds;
        this.oxmIdsSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }

//
        @Override
        public OFTableFeaturePropWildcards build() {
            List<U32> oxmIds = this.oxmIdsSet ? this.oxmIds : DEFAULT_OXM_IDS;
            if(oxmIds == null)
                throw new NullPointerException("Property oxmIds must not be null");


            return new OFTableFeaturePropWildcardsVer15(
                    oxmIds
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFTableFeaturePropWildcards> {
        @Override
        public OFTableFeaturePropWildcards readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0xa
            short type = bb.readShort();
            if(type != (short) 0xa)
                throw new OFParseError("Wrong type: Expected=0xa(0xa), got="+type);
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
            List<U32> oxmIds = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), U32.READER);

            OFTableFeaturePropWildcardsVer15 tableFeaturePropWildcardsVer15 = new OFTableFeaturePropWildcardsVer15(
                    oxmIds
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", tableFeaturePropWildcardsVer15);
            return tableFeaturePropWildcardsVer15;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFTableFeaturePropWildcardsVer15Funnel FUNNEL = new OFTableFeaturePropWildcardsVer15Funnel();
    static class OFTableFeaturePropWildcardsVer15Funnel implements Funnel<OFTableFeaturePropWildcardsVer15> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFTableFeaturePropWildcardsVer15 message, PrimitiveSink sink) {
            // fixed value property type = 0xa
            sink.putShort((short) 0xa);
            // FIXME: skip funnel of length
            FunnelUtils.putList(message.oxmIds, sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFTableFeaturePropWildcardsVer15> {
        @Override
        public void write(ByteBuf bb, OFTableFeaturePropWildcardsVer15 message) {
            int startIndex = bb.writerIndex();
            // fixed value property type = 0xa
            bb.writeShort((short) 0xa);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            ChannelUtils.writeList(bb, message.oxmIds);

            // update length field
            int length = bb.writerIndex() - startIndex;
            if (length > MAXIMUM_LENGTH) {
                throw new IllegalArgumentException("OFTableFeaturePropWildcardsVer15: message length (" + length + ") exceeds maximum (0xFFFF)");
            }
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFTableFeaturePropWildcardsVer15(");
        b.append("oxmIds=").append(oxmIds);
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
        OFTableFeaturePropWildcardsVer15 other = (OFTableFeaturePropWildcardsVer15) obj;

        if (oxmIds == null) {
            if (other.oxmIds != null)
                return false;
        } else if (!oxmIds.equals(other.oxmIds))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((oxmIds == null) ? 0 : oxmIds.hashCode());
        return result;
    }

}