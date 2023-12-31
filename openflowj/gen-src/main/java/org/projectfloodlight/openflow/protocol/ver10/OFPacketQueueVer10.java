// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_class.java
// Do not modify

package org.projectfloodlight.openflow.protocol.ver10;

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

class OFPacketQueueVer10 implements OFPacketQueue {
    private static final Logger logger = LoggerFactory.getLogger(OFPacketQueueVer10.class);
    // version: 1.0
    final static byte WIRE_VERSION = 1;
    final static int MINIMUM_LENGTH = 8;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static long DEFAULT_QUEUE_ID = 0x0L;
        private final static List<OFQueueProp> DEFAULT_PROPERTIES = ImmutableList.<OFQueueProp>of();

    // OF message fields
    private final long queueId;
    private final List<OFQueueProp> properties;
//
    // Immutable default instance
    final static OFPacketQueueVer10 DEFAULT = new OFPacketQueueVer10(
        DEFAULT_QUEUE_ID, DEFAULT_PROPERTIES
    );

    // package private constructor - used by readers, builders, and factory
    OFPacketQueueVer10(long queueId, List<OFQueueProp> properties) {
        if(properties == null) {
            throw new NullPointerException("OFPacketQueueVer10: property properties cannot be null");
        }
        this.queueId = U32.normalize(queueId);
        this.properties = properties;
    }

    // Accessors for OF message fields
    @Override
    public long getQueueId() {
        return queueId;
    }

    @Override
    public List<OFQueueProp> getProperties() {
        return properties;
    }

    @Override
    public OFPort getPort()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property port not supported in version 1.0");
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
    }



    public OFPacketQueue.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFPacketQueue.Builder {
        final OFPacketQueueVer10 parentMessage;

        // OF message fields
        private boolean queueIdSet;
        private long queueId;
        private boolean propertiesSet;
        private List<OFQueueProp> properties;

        BuilderWithParent(OFPacketQueueVer10 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public long getQueueId() {
        return queueId;
    }

    @Override
    public OFPacketQueue.Builder setQueueId(long queueId) {
        this.queueId = queueId;
        this.queueIdSet = true;
        return this;
    }
    @Override
    public List<OFQueueProp> getProperties() {
        return properties;
    }

    @Override
    public OFPacketQueue.Builder setProperties(List<OFQueueProp> properties) {
        this.properties = properties;
        this.propertiesSet = true;
        return this;
    }
    @Override
    public OFPort getPort()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property port not supported in version 1.0");
    }

    @Override
    public OFPacketQueue.Builder setPort(OFPort port) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property port not supported in version 1.0");
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
    }



        @Override
        public OFPacketQueue build() {
                long queueId = this.queueIdSet ? this.queueId : parentMessage.queueId;
                List<OFQueueProp> properties = this.propertiesSet ? this.properties : parentMessage.properties;
                if(properties == null)
                    throw new NullPointerException("Property properties must not be null");

                //
                return new OFPacketQueueVer10(
                    queueId,
                    properties
                );
        }

    }

    static class Builder implements OFPacketQueue.Builder {
        // OF message fields
        private boolean queueIdSet;
        private long queueId;
        private boolean propertiesSet;
        private List<OFQueueProp> properties;

    @Override
    public long getQueueId() {
        return queueId;
    }

    @Override
    public OFPacketQueue.Builder setQueueId(long queueId) {
        this.queueId = queueId;
        this.queueIdSet = true;
        return this;
    }
    @Override
    public List<OFQueueProp> getProperties() {
        return properties;
    }

    @Override
    public OFPacketQueue.Builder setProperties(List<OFQueueProp> properties) {
        this.properties = properties;
        this.propertiesSet = true;
        return this;
    }
    @Override
    public OFPort getPort()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property port not supported in version 1.0");
    }

    @Override
    public OFPacketQueue.Builder setPort(OFPort port) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property port not supported in version 1.0");
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
    }

//
        @Override
        public OFPacketQueue build() {
            long queueId = this.queueIdSet ? this.queueId : DEFAULT_QUEUE_ID;
            List<OFQueueProp> properties = this.propertiesSet ? this.properties : DEFAULT_PROPERTIES;
            if(properties == null)
                throw new NullPointerException("Property properties must not be null");


            return new OFPacketQueueVer10(
                    queueId,
                    properties
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFPacketQueue> {
        @Override
        public OFPacketQueue readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
            long queueId = U32.f(bb.readInt());
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
            // pad: 2 bytes
            bb.skipBytes(2);
            List<OFQueueProp> properties = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), OFQueuePropVer10.READER);

            OFPacketQueueVer10 packetQueueVer10 = new OFPacketQueueVer10(
                    queueId,
                      properties
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", packetQueueVer10);
            return packetQueueVer10;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFPacketQueueVer10Funnel FUNNEL = new OFPacketQueueVer10Funnel();
    static class OFPacketQueueVer10Funnel implements Funnel<OFPacketQueueVer10> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFPacketQueueVer10 message, PrimitiveSink sink) {
            sink.putLong(message.queueId);
            // FIXME: skip funnel of length
            // skip pad (2 bytes)
            FunnelUtils.putList(message.properties, sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFPacketQueueVer10> {
        @Override
        public void write(ByteBuf bb, OFPacketQueueVer10 message) {
            int startIndex = bb.writerIndex();
            bb.writeInt(U32.t(message.queueId));
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            // pad: 2 bytes
            bb.writeZero(2);
            ChannelUtils.writeList(bb, message.properties);

            // update length field
            int length = bb.writerIndex() - startIndex;
            if (length > MAXIMUM_LENGTH) {
                throw new IllegalArgumentException("OFPacketQueueVer10: message length (" + length + ") exceeds maximum (0xFFFF)");
            }
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFPacketQueueVer10(");
        b.append("queueId=").append(queueId);
        b.append(", ");
        b.append("properties=").append(properties);
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
        OFPacketQueueVer10 other = (OFPacketQueueVer10) obj;

        if( queueId != other.queueId)
            return false;
        if (properties == null) {
            if (other.properties != null)
                return false;
        } else if (!properties.equals(other.properties))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime *  (int) (queueId ^ (queueId >>> 32));
        result = prime * result + ((properties == null) ? 0 : properties.hashCode());
        return result;
    }

}
