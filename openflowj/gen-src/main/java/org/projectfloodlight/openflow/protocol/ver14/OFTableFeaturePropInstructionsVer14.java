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
import java.util.List;
import com.google.common.collect.ImmutableList;
import java.util.Set;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFTableFeaturePropInstructionsVer14 implements OFTableFeaturePropInstructions {
    private static final Logger logger = LoggerFactory.getLogger(OFTableFeaturePropInstructionsVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int MINIMUM_LENGTH = 4;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static List<OFInstructionId> DEFAULT_INSTRUCTION_IDS = ImmutableList.<OFInstructionId>of();

    // OF message fields
    private final List<OFInstructionId> instructionIds;
//
    // Immutable default instance
    final static OFTableFeaturePropInstructionsVer14 DEFAULT = new OFTableFeaturePropInstructionsVer14(
        DEFAULT_INSTRUCTION_IDS
    );

    // package private constructor - used by readers, builders, and factory
    OFTableFeaturePropInstructionsVer14(List<OFInstructionId> instructionIds) {
        if(instructionIds == null) {
            throw new NullPointerException("OFTableFeaturePropInstructionsVer14: property instructionIds cannot be null");
        }
        this.instructionIds = instructionIds;
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x0;
    }

    @Override
    public List<OFInstructionId> getInstructionIds() {
        return instructionIds;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFTableFeaturePropInstructions.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFTableFeaturePropInstructions.Builder {
        final OFTableFeaturePropInstructionsVer14 parentMessage;

        // OF message fields
        private boolean instructionIdsSet;
        private List<OFInstructionId> instructionIds;

        BuilderWithParent(OFTableFeaturePropInstructionsVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x0;
    }

    @Override
    public List<OFInstructionId> getInstructionIds() {
        return instructionIds;
    }

    @Override
    public OFTableFeaturePropInstructions.Builder setInstructionIds(List<OFInstructionId> instructionIds) {
        this.instructionIds = instructionIds;
        this.instructionIdsSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFTableFeaturePropInstructions build() {
                List<OFInstructionId> instructionIds = this.instructionIdsSet ? this.instructionIds : parentMessage.instructionIds;
                if(instructionIds == null)
                    throw new NullPointerException("Property instructionIds must not be null");

                //
                return new OFTableFeaturePropInstructionsVer14(
                    instructionIds
                );
        }

    }

    static class Builder implements OFTableFeaturePropInstructions.Builder {
        // OF message fields
        private boolean instructionIdsSet;
        private List<OFInstructionId> instructionIds;

    @Override
    public int getType() {
        return 0x0;
    }

    @Override
    public List<OFInstructionId> getInstructionIds() {
        return instructionIds;
    }

    @Override
    public OFTableFeaturePropInstructions.Builder setInstructionIds(List<OFInstructionId> instructionIds) {
        this.instructionIds = instructionIds;
        this.instructionIdsSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFTableFeaturePropInstructions build() {
            List<OFInstructionId> instructionIds = this.instructionIdsSet ? this.instructionIds : DEFAULT_INSTRUCTION_IDS;
            if(instructionIds == null)
                throw new NullPointerException("Property instructionIds must not be null");


            return new OFTableFeaturePropInstructionsVer14(
                    instructionIds
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFTableFeaturePropInstructions> {
        @Override
        public OFTableFeaturePropInstructions readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x0
            short type = bb.readShort();
            if(type != (short) 0x0)
                throw new OFParseError("Wrong type: Expected=0x0(0x0), got="+type);
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
            List<OFInstructionId> instructionIds = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), OFInstructionIdVer14.READER);
            // align message to 8 bytes (length does not contain alignment)
            bb.skipBytes(((length + 7)/8 * 8 ) - length );

            OFTableFeaturePropInstructionsVer14 tableFeaturePropInstructionsVer14 = new OFTableFeaturePropInstructionsVer14(
                    instructionIds
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", tableFeaturePropInstructionsVer14);
            return tableFeaturePropInstructionsVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFTableFeaturePropInstructionsVer14Funnel FUNNEL = new OFTableFeaturePropInstructionsVer14Funnel();
    static class OFTableFeaturePropInstructionsVer14Funnel implements Funnel<OFTableFeaturePropInstructionsVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFTableFeaturePropInstructionsVer14 message, PrimitiveSink sink) {
            // fixed value property type = 0x0
            sink.putShort((short) 0x0);
            // FIXME: skip funnel of length
            FunnelUtils.putList(message.instructionIds, sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFTableFeaturePropInstructionsVer14> {
        @Override
        public void write(ByteBuf bb, OFTableFeaturePropInstructionsVer14 message) {
            int startIndex = bb.writerIndex();
            // fixed value property type = 0x0
            bb.writeShort((short) 0x0);
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            ChannelUtils.writeList(bb, message.instructionIds);

            // update length field
            int length = bb.writerIndex() - startIndex;
            int alignedLength = ((length + 7)/8 * 8);
            if (length > MAXIMUM_LENGTH) {
                throw new IllegalArgumentException("OFTableFeaturePropInstructionsVer14: message length (" + length + ") exceeds maximum (0xFFFF)");
            }
            bb.setShort(lengthIndex, length);
            // align message to 8 bytes
            bb.writeZero(alignedLength - length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFTableFeaturePropInstructionsVer14(");
        b.append("instructionIds=").append(instructionIds);
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
        OFTableFeaturePropInstructionsVer14 other = (OFTableFeaturePropInstructionsVer14) obj;

        if (instructionIds == null) {
            if (other.instructionIds != null)
                return false;
        } else if (!instructionIds.equals(other.instructionIds))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((instructionIds == null) ? 0 : instructionIds.hashCode());
        return result;
    }

}
