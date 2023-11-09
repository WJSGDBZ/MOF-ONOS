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

class OFAsyncConfigPropRoleStatusSlaveVer14 implements OFAsyncConfigPropRoleStatusSlave {
    private static final Logger logger = LoggerFactory.getLogger(OFAsyncConfigPropRoleStatusSlaveVer14.class);
    // version: 1.4
    final static byte WIRE_VERSION = 5;
    final static int LENGTH = 8;

        private final static long DEFAULT_MASK = 0x0L;

    // OF message fields
    private final long mask;
//
    // Immutable default instance
    final static OFAsyncConfigPropRoleStatusSlaveVer14 DEFAULT = new OFAsyncConfigPropRoleStatusSlaveVer14(
        DEFAULT_MASK
    );

    // package private constructor - used by readers, builders, and factory
    OFAsyncConfigPropRoleStatusSlaveVer14(long mask) {
        this.mask = U32.normalize(mask);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x6;
    }

    @Override
    public long getMask() {
        return mask;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



    public OFAsyncConfigPropRoleStatusSlave.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFAsyncConfigPropRoleStatusSlave.Builder {
        final OFAsyncConfigPropRoleStatusSlaveVer14 parentMessage;

        // OF message fields
        private boolean maskSet;
        private long mask;

        BuilderWithParent(OFAsyncConfigPropRoleStatusSlaveVer14 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x6;
    }

    @Override
    public long getMask() {
        return mask;
    }

    @Override
    public OFAsyncConfigPropRoleStatusSlave.Builder setMask(long mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }



        @Override
        public OFAsyncConfigPropRoleStatusSlave build() {
                long mask = this.maskSet ? this.mask : parentMessage.mask;

                //
                return new OFAsyncConfigPropRoleStatusSlaveVer14(
                    mask
                );
        }

    }

    static class Builder implements OFAsyncConfigPropRoleStatusSlave.Builder {
        // OF message fields
        private boolean maskSet;
        private long mask;

    @Override
    public int getType() {
        return 0x6;
    }

    @Override
    public long getMask() {
        return mask;
    }

    @Override
    public OFAsyncConfigPropRoleStatusSlave.Builder setMask(long mask) {
        this.mask = mask;
        this.maskSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_14;
    }

//
        @Override
        public OFAsyncConfigPropRoleStatusSlave build() {
            long mask = this.maskSet ? this.mask : DEFAULT_MASK;


            return new OFAsyncConfigPropRoleStatusSlaveVer14(
                    mask
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFAsyncConfigPropRoleStatusSlave> {
        @Override
        public OFAsyncConfigPropRoleStatusSlave readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x6
            short type = bb.readShort();
            if(type != (short) 0x6)
                throw new OFParseError("Wrong type: Expected=0x6(0x6), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 8)
                throw new OFParseError("Wrong length: Expected=8(8), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            long mask = U32.f(bb.readInt());

            OFAsyncConfigPropRoleStatusSlaveVer14 asyncConfigPropRoleStatusSlaveVer14 = new OFAsyncConfigPropRoleStatusSlaveVer14(
                    mask
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", asyncConfigPropRoleStatusSlaveVer14);
            return asyncConfigPropRoleStatusSlaveVer14;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFAsyncConfigPropRoleStatusSlaveVer14Funnel FUNNEL = new OFAsyncConfigPropRoleStatusSlaveVer14Funnel();
    static class OFAsyncConfigPropRoleStatusSlaveVer14Funnel implements Funnel<OFAsyncConfigPropRoleStatusSlaveVer14> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFAsyncConfigPropRoleStatusSlaveVer14 message, PrimitiveSink sink) {
            // fixed value property type = 0x6
            sink.putShort((short) 0x6);
            // fixed value property length = 8
            sink.putShort((short) 0x8);
            sink.putLong(message.mask);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFAsyncConfigPropRoleStatusSlaveVer14> {
        @Override
        public void write(ByteBuf bb, OFAsyncConfigPropRoleStatusSlaveVer14 message) {
            // fixed value property type = 0x6
            bb.writeShort((short) 0x6);
            // fixed value property length = 8
            bb.writeShort((short) 0x8);
            bb.writeInt(U32.t(message.mask));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFAsyncConfigPropRoleStatusSlaveVer14(");
        b.append("mask=").append(mask);
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
        OFAsyncConfigPropRoleStatusSlaveVer14 other = (OFAsyncConfigPropRoleStatusSlaveVer14) obj;

        if( mask != other.mask)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (mask ^ (mask >>> 32));
        return result;
    }

}
