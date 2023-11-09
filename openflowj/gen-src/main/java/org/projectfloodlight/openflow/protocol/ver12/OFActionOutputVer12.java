// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver12;

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

class OFActionOutputVer12 implements OFActionOutput {
    private static final Logger logger = LoggerFactory.getLogger(OFActionOutputVer12.class);
    // version: 1.2
    final static byte WIRE_VERSION = 3;
    final static int LENGTH = 16;

        private final static OFPort DEFAULT_PORT = OFPort.ANY;
        private final static int DEFAULT_MAX_LEN = 0x0;

    // OF message fields
    private final OFPort port;
    private final int maxLen;
//
    // Immutable default instance
    final static OFActionOutputVer12 DEFAULT = new OFActionOutputVer12(
        DEFAULT_PORT, DEFAULT_MAX_LEN
    );

    // package private constructor - used by readers, builders, and factory
    OFActionOutputVer12(OFPort port, int maxLen) {
        if(port == null) {
            throw new NullPointerException("OFActionOutputVer12: property port cannot be null");
        }
        this.port = port;
        this.maxLen = U16.normalize(maxLen);
    }

    // Accessors for OF message fields
    @Override
    public OFActionType getType() {
        return OFActionType.OUTPUT;
    }

    @Override
    public OFPort getPort() {
        return port;
    }

    @Override
    public int getMaxLen() {
        return maxLen;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }



    public OFActionOutput.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFActionOutput.Builder {
        final OFActionOutputVer12 parentMessage;

        // OF message fields
        private boolean portSet;
        private OFPort port;
        private boolean maxLenSet;
        private int maxLen;

        BuilderWithParent(OFActionOutputVer12 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public OFActionType getType() {
        return OFActionType.OUTPUT;
    }

    @Override
    public OFPort getPort() {
        return port;
    }

    @Override
    public OFActionOutput.Builder setPort(OFPort port) {
        this.port = port;
        this.portSet = true;
        return this;
    }
    @Override
    public int getMaxLen() {
        return maxLen;
    }

    @Override
    public OFActionOutput.Builder setMaxLen(int maxLen) {
        this.maxLen = maxLen;
        this.maxLenSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }



        @Override
        public OFActionOutput build() {
                OFPort port = this.portSet ? this.port : parentMessage.port;
                if(port == null)
                    throw new NullPointerException("Property port must not be null");
                int maxLen = this.maxLenSet ? this.maxLen : parentMessage.maxLen;

                //
                return new OFActionOutputVer12(
                    port,
                    maxLen
                );
        }

    }

    static class Builder implements OFActionOutput.Builder {
        // OF message fields
        private boolean portSet;
        private OFPort port;
        private boolean maxLenSet;
        private int maxLen;

    @Override
    public OFActionType getType() {
        return OFActionType.OUTPUT;
    }

    @Override
    public OFPort getPort() {
        return port;
    }

    @Override
    public OFActionOutput.Builder setPort(OFPort port) {
        this.port = port;
        this.portSet = true;
        return this;
    }
    @Override
    public int getMaxLen() {
        return maxLen;
    }

    @Override
    public OFActionOutput.Builder setMaxLen(int maxLen) {
        this.maxLen = maxLen;
        this.maxLenSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_12;
    }

//
        @Override
        public OFActionOutput build() {
            OFPort port = this.portSet ? this.port : DEFAULT_PORT;
            if(port == null)
                throw new NullPointerException("Property port must not be null");
            int maxLen = this.maxLenSet ? this.maxLen : DEFAULT_MAX_LEN;


            return new OFActionOutputVer12(
                    port,
                    maxLen
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFActionOutput> {
        @Override
        public OFActionOutput readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0
            short type = bb.readShort();
            if(type != (short) 0x0)
                throw new OFParseError("Wrong type: Expected=OFActionType.OUTPUT(0), got="+type);
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
            OFPort port = OFPort.read4Bytes(bb);
            int maxLen = U16.f(bb.readShort());
            // pad: 6 bytes
            bb.skipBytes(6);

            OFActionOutputVer12 actionOutputVer12 = new OFActionOutputVer12(
                    port,
                      maxLen
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", actionOutputVer12);
            return actionOutputVer12;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFActionOutputVer12Funnel FUNNEL = new OFActionOutputVer12Funnel();
    static class OFActionOutputVer12Funnel implements Funnel<OFActionOutputVer12> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFActionOutputVer12 message, PrimitiveSink sink) {
            // fixed value property type = 0
            sink.putShort((short) 0x0);
            // fixed value property length = 16
            sink.putShort((short) 0x10);
            message.port.putTo(sink);
            sink.putInt(message.maxLen);
            // skip pad (6 bytes)
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFActionOutputVer12> {
        @Override
        public void write(ByteBuf bb, OFActionOutputVer12 message) {
            // fixed value property type = 0
            bb.writeShort((short) 0x0);
            // fixed value property length = 16
            bb.writeShort((short) 0x10);
            message.port.write4Bytes(bb);
            bb.writeShort(U16.t(message.maxLen));
            // pad: 6 bytes
            bb.writeZero(6);


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFActionOutputVer12(");
        b.append("port=").append(port);
        b.append(", ");
        b.append("maxLen=").append(maxLen);
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
        OFActionOutputVer12 other = (OFActionOutputVer12) obj;

        if (port == null) {
            if (other.port != null)
                return false;
        } else if (!port.equals(other.port))
            return false;
        if( maxLen != other.maxLen)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((port == null) ? 0 : port.hashCode());
        result = prime * result + maxLen;
        return result;
    }

}
