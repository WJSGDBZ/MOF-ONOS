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

class OFInstructionBsnInternalPriorityVer14 implements OFInstructionBsnInternalPriority {
    private static final Logger logger = LoggerFactory.getLogger(OFInstructionBsnInternalPriorityVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 16;

        private final static long DEFAULT_VALUE = 0x0L;

    // OF message fields
    private final long value;
//
    // Immutable default instance
    final static OFInstructionBsnInternalPriorityVer14 DEFAULT = new OFInstructionBsnInternalPriorityVer14(
        DEFAULT_VALUE
    );

    // package private constructor - used by readers, builders, and factory
    OFInstructionBsnInternalPriorityVer14(long value) {
        this.value = U32.normalize(value);
    }

    // Accessors for OF message fields
    @Override
    public OFInstructionType getType() {
        return OFInstructionType.EXPERIMENTER;
    }

    @Override
    public long getExperimenter() {
        return 0x5c16c7L;
    }

    @Override
    public long getSubtype() {
        return 0xcL;
    }

    @Override
    public long getValue() {
        return value;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFInstructionBsnInternalPriority.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFInstructionBsnInternalPriority.Builder {
        final OFInstructionBsnInternalPriorityVer14 parentMessage;

        // OF message fields
        private boolean valueSet;
        private long value;

        BuilderWithParent(OFInstructionBsnInternalPriorityVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFInstructionType getType() {
        return OFInstructionType.EXPERIMENTER;
    }

    @Override
    public long getExperimenter() {
        return 0x5c16c7L;
    }

    @Override
    public long getSubtype() {
        return 0xcL;
    }

    @Override
    public long getValue() {
        return value;
    }

    @Override
    public OFInstructionBsnInternalPriority.Builder setValue(long value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFInstructionBsnInternalPriority build() {
                long value = this.valueSet ? this.value : parentMessage.value;

                //
                return new OFInstructionBsnInternalPriorityVer14(
                    value
                );
        }

    }

    static class Builder implements OFInstructionBsnInternalPriority.Builder {
        // OF message fields
        private boolean valueSet;
        private long value;

    @Override
    public OFInstructionType getType() {
        return OFInstructionType.EXPERIMENTER;
    }

    @Override
    public long getExperimenter() {
        return 0x5c16c7L;
    }

    @Override
    public long getSubtype() {
        return 0xcL;
    }

    @Override
    public long getValue() {
        return value;
    }

    @Override
    public OFInstructionBsnInternalPriority.Builder setValue(long value) {
        this.value = value;
        this.valueSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFInstructionBsnInternalPriority build() {
            long value = this.valueSet ? this.value : DEFAULT_VALUE;


            return new OFInstructionBsnInternalPriorityVer14(
                    value
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFInstructionBsnInternalPriority> {
        @Override
        public OFInstructionBsnInternalPriority readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 65535
            short type = bb.readShort();
            if(type != (short) 0xffff)
                throw new OFParseError("Wrong type: Expected=OFInstructionType.EXPERIMENTER(65535), got="+type);
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
            // fixed value property experimenter == 0x5c16c7L
            int experimenter = bb.readInt();
            if(experimenter != 0x5c16c7)
                throw new OFParseError("Wrong experimenter: Expected=0x5c16c7L(0x5c16c7L), got="+experimenter);
            // fixed value property subtype == 0xcL
            int subtype = bb.readInt();
            if(subtype != 0xc)
                throw new OFParseError("Wrong subtype: Expected=0xcL(0xcL), got="+subtype);
            long value = U32.f(bb.readInt());

            OFInstructionBsnInternalPriorityVer14 instructionBsnInternalPriorityVer14 = new OFInstructionBsnInternalPriorityVer14(
                    value
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", instructionBsnInternalPriorityVer14);
            return instructionBsnInternalPriorityVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFInstructionBsnInternalPriorityVer14Funnel FUNNEL = new OFInstructionBsnInternalPriorityVer14Funnel();
    static class OFInstructionBsnInternalPriorityVer14Funnel implements Funnel<OFInstructionBsnInternalPriorityVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFInstructionBsnInternalPriorityVer14 message, PrimitiveSink sink) {
            // fixed value property type = 65535
            sink.putShort((short) 0xffff);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            // fixed value property experimenter = 0x5c16c7L
            sink.putInt(0x5c16c7);
            // fixed value property subtype = 0xcL
            sink.putInt(0xc);
            sink.putLong(message.value);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFInstructionBsnInternalPriorityVer14> {
        @Override
        public void write(ByteBuf bb, OFInstructionBsnInternalPriorityVer14 message) {
            // fixed value property type = 65535
            bb.writeShort((short) 0xffff);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            // fixed value property experimenter = 0x5c16c7L
            bb.writeInt(0x5c16c7);
            // fixed value property subtype = 0xcL
            bb.writeInt(0xc);
            bb.writeInt(U32.t(message.value));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFInstructionBsnInternalPriorityVer14(");
        b.append("value=").append(value);
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
        OFInstructionBsnInternalPriorityVer14 other = (OFInstructionBsnInternalPriorityVer14) obj;

        if( value != other.value)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (value ^ (value >>> 32));
        return result;
    }

}