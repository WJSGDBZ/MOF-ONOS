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
import java.util.Set;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFBsnTlvHashGtpPortMatchVer15 implements OFBsnTlvHashGtpPortMatch {
    private static final Logger logger = LoggerFactory.getLogger(OFBsnTlvHashGtpPortMatchVer15.class);
    // version: 1.5
    final static byte WIRE_VERSION = 6;
    final static int LENGTH = 9;

        private final static int DEFAULT_SRC_PORT = 0x0;
        private final static int DEFAULT_DST_PORT = 0x0;

    // OF message fields
    private final OFBsnHashGtpPortMatch match;
    private final int srcPort;
    private final int dstPort;
//

    // package private constructor - used by readers, builders, and factory
    OFBsnTlvHashGtpPortMatchVer15(OFBsnHashGtpPortMatch match, int srcPort, int dstPort) {
        if(match == null) {
            throw new NullPointerException("OFBsnTlvHashGtpPortMatchVer15: property match cannot be null");
        }
        this.match = match;
        this.srcPort = U16.normalize(srcPort);
        this.dstPort = U16.normalize(dstPort);
    }

    // Accessors for OF message fields
    @Override
    public int getType() {
        return 0x69;
    }

    @Override
    public OFBsnHashGtpPortMatch getMatch() {
        return match;
    }

    @Override
    public int getSrcPort() {
        return srcPort;
    }

    @Override
    public int getDstPort() {
        return dstPort;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



    public OFBsnTlvHashGtpPortMatch.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFBsnTlvHashGtpPortMatch.Builder {
        final OFBsnTlvHashGtpPortMatchVer15 parentMessage;

        // OF message fields
        private boolean matchSet;
        private OFBsnHashGtpPortMatch match;
        private boolean srcPortSet;
        private int srcPort;
        private boolean dstPortSet;
        private int dstPort;

        BuilderWithParent(OFBsnTlvHashGtpPortMatchVer15 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public int getType() {
        return 0x69;
    }

    @Override
    public OFBsnHashGtpPortMatch getMatch() {
        return match;
    }

    @Override
    public OFBsnTlvHashGtpPortMatch.Builder setMatch(OFBsnHashGtpPortMatch match) {
        this.match = match;
        this.matchSet = true;
        return this;
    }
    @Override
    public int getSrcPort() {
        return srcPort;
    }

    @Override
    public OFBsnTlvHashGtpPortMatch.Builder setSrcPort(int srcPort) {
        this.srcPort = srcPort;
        this.srcPortSet = true;
        return this;
    }
    @Override
    public int getDstPort() {
        return dstPort;
    }

    @Override
    public OFBsnTlvHashGtpPortMatch.Builder setDstPort(int dstPort) {
        this.dstPort = dstPort;
        this.dstPortSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



        @Override
        public OFBsnTlvHashGtpPortMatch build() {
                OFBsnHashGtpPortMatch match = this.matchSet ? this.match : parentMessage.match;
                if(match == null)
                    throw new NullPointerException("Property match must not be null");
                int srcPort = this.srcPortSet ? this.srcPort : parentMessage.srcPort;
                int dstPort = this.dstPortSet ? this.dstPort : parentMessage.dstPort;

                //
                return new OFBsnTlvHashGtpPortMatchVer15(
                    match,
                    srcPort,
                    dstPort
                );
        }

    }

    static class Builder implements OFBsnTlvHashGtpPortMatch.Builder {
        // OF message fields
        private boolean matchSet;
        private OFBsnHashGtpPortMatch match;
        private boolean srcPortSet;
        private int srcPort;
        private boolean dstPortSet;
        private int dstPort;

    @Override
    public int getType() {
        return 0x69;
    }

    @Override
    public OFBsnHashGtpPortMatch getMatch() {
        return match;
    }

    @Override
    public OFBsnTlvHashGtpPortMatch.Builder setMatch(OFBsnHashGtpPortMatch match) {
        this.match = match;
        this.matchSet = true;
        return this;
    }
    @Override
    public int getSrcPort() {
        return srcPort;
    }

    @Override
    public OFBsnTlvHashGtpPortMatch.Builder setSrcPort(int srcPort) {
        this.srcPort = srcPort;
        this.srcPortSet = true;
        return this;
    }
    @Override
    public int getDstPort() {
        return dstPort;
    }

    @Override
    public OFBsnTlvHashGtpPortMatch.Builder setDstPort(int dstPort) {
        this.dstPort = dstPort;
        this.dstPortSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }

//
        @Override
        public OFBsnTlvHashGtpPortMatch build() {
            if(!this.matchSet)
                throw new IllegalStateException("Property match doesn't have default value -- must be set");
            if(match == null)
                throw new NullPointerException("Property match must not be null");
            int srcPort = this.srcPortSet ? this.srcPort : DEFAULT_SRC_PORT;
            int dstPort = this.dstPortSet ? this.dstPort : DEFAULT_DST_PORT;


            return new OFBsnTlvHashGtpPortMatchVer15(
                    match,
                    srcPort,
                    dstPort
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFBsnTlvHashGtpPortMatch> {
        @Override
        public OFBsnTlvHashGtpPortMatch readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            // fixed value property type == 0x69
            short type = bb.readShort();
            if(type != (short) 0x69)
                throw new OFParseError("Wrong type: Expected=0x69(0x69), got="+type);
            int length = U16.f(bb.readShort());
            if(length != 9)
                throw new OFParseError("Wrong length: Expected=9(9), got="+length);
            if(bb.readableBytes() + (bb.readerIndex() - start) < length) {
                // Buffer does not have all data yet
                bb.readerIndex(start);
                return null;
            }
            if(logger.isTraceEnabled())
                logger.trace("readFrom - length={}", length);
            OFBsnHashGtpPortMatch match = OFBsnHashGtpPortMatchSerializerVer15.readFrom(bb);
            int srcPort = U16.f(bb.readShort());
            int dstPort = U16.f(bb.readShort());

            OFBsnTlvHashGtpPortMatchVer15 bsnTlvHashGtpPortMatchVer15 = new OFBsnTlvHashGtpPortMatchVer15(
                    match,
                      srcPort,
                      dstPort
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", bsnTlvHashGtpPortMatchVer15);
            return bsnTlvHashGtpPortMatchVer15;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFBsnTlvHashGtpPortMatchVer15Funnel FUNNEL = new OFBsnTlvHashGtpPortMatchVer15Funnel();
    static class OFBsnTlvHashGtpPortMatchVer15Funnel implements Funnel<OFBsnTlvHashGtpPortMatchVer15> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFBsnTlvHashGtpPortMatchVer15 message, PrimitiveSink sink) {
            // fixed value property type = 0x69
            sink.putShort((short) 0x69);
            // fixed value property length = 9
            sink.putShort((short) 0x9);
            OFBsnHashGtpPortMatchSerializerVer15.putTo(message.match, sink);
            sink.putInt(message.srcPort);
            sink.putInt(message.dstPort);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFBsnTlvHashGtpPortMatchVer15> {
        @Override
        public void write(ByteBuf bb, OFBsnTlvHashGtpPortMatchVer15 message) {
            // fixed value property type = 0x69
            bb.writeShort((short) 0x69);
            // fixed value property length = 9
            bb.writeShort((short) 0x9);
            OFBsnHashGtpPortMatchSerializerVer15.writeTo(bb, message.match);
            bb.writeShort(U16.t(message.srcPort));
            bb.writeShort(U16.t(message.dstPort));


        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFBsnTlvHashGtpPortMatchVer15(");
        b.append("match=").append(match);
        b.append(", ");
        b.append("srcPort=").append(srcPort);
        b.append(", ");
        b.append("dstPort=").append(dstPort);
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
        OFBsnTlvHashGtpPortMatchVer15 other = (OFBsnTlvHashGtpPortMatchVer15) obj;

        if (match == null) {
            if (other.match != null)
                return false;
        } else if (!match.equals(other.match))
            return false;
        if( srcPort != other.srcPort)
            return false;
        if( dstPort != other.dstPort)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((match == null) ? 0 : match.hashCode());
        result = prime * result + srcPort;
        result = prime * result + dstPort;
        return result;
    }

}
