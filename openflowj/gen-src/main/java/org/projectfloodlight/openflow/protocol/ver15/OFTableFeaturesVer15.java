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
import com.google.common.collect.ImmutableSet;
import java.util.List;
import com.google.common.collect.ImmutableList;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

class OFTableFeaturesVer15 implements OFTableFeatures {
    private static final Logger logger = LoggerFactory.getLogger(OFTableFeaturesVer15.class);
    // version: 1.5
    final static byte WIRE_VERSION = 6;
    final static int MINIMUM_LENGTH = 64;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static TableId DEFAULT_TABLE_ID = TableId.ALL;
        private final static Set<OFTableFeatureFlag> DEFAULT_FEATURES = ImmutableSet.<OFTableFeatureFlag>of();
        private final static String DEFAULT_NAME = "";
        private final static U64 DEFAULT_METADATA_MATCH = U64.ZERO;
        private final static U64 DEFAULT_METADATA_WRITE = U64.ZERO;
        private final static Set<OFTableConfig> DEFAULT_CAPABILITIES = ImmutableSet.<OFTableConfig>of();
        private final static long DEFAULT_MAX_ENTRIES = 0x0L;
        private final static List<OFTableFeatureProp> DEFAULT_PROPERTIES = ImmutableList.<OFTableFeatureProp>of();

    // OF message fields
    private final TableId tableId;
    private final OFTableFeaturesCommand command;
    private final Set<OFTableFeatureFlag> features;
    private final String name;
    private final U64 metadataMatch;
    private final U64 metadataWrite;
    private final Set<OFTableConfig> capabilities;
    private final long maxEntries;
    private final List<OFTableFeatureProp> properties;
//

    // package private constructor - used by readers, builders, and factory
    OFTableFeaturesVer15(TableId tableId, OFTableFeaturesCommand command, Set<OFTableFeatureFlag> features, String name, U64 metadataMatch, U64 metadataWrite, Set<OFTableConfig> capabilities, long maxEntries, List<OFTableFeatureProp> properties) {
        if(tableId == null) {
            throw new NullPointerException("OFTableFeaturesVer15: property tableId cannot be null");
        }
        if(command == null) {
            throw new NullPointerException("OFTableFeaturesVer15: property command cannot be null");
        }
        if(features == null) {
            throw new NullPointerException("OFTableFeaturesVer15: property features cannot be null");
        }
        if(name == null) {
            throw new NullPointerException("OFTableFeaturesVer15: property name cannot be null");
        }
        if(metadataMatch == null) {
            throw new NullPointerException("OFTableFeaturesVer15: property metadataMatch cannot be null");
        }
        if(metadataWrite == null) {
            throw new NullPointerException("OFTableFeaturesVer15: property metadataWrite cannot be null");
        }
        if(capabilities == null) {
            throw new NullPointerException("OFTableFeaturesVer15: property capabilities cannot be null");
        }
        if(properties == null) {
            throw new NullPointerException("OFTableFeaturesVer15: property properties cannot be null");
        }
        this.tableId = tableId;
        this.command = command;
        this.features = features;
        this.name = name;
        this.metadataMatch = metadataMatch;
        this.metadataWrite = metadataWrite;
        this.capabilities = capabilities;
        this.maxEntries = U32.normalize(maxEntries);
        this.properties = properties;
    }

    // Accessors for OF message fields
    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public U64 getMetadataMatch() {
        return metadataMatch;
    }

    @Override
    public U64 getMetadataWrite() {
        return metadataWrite;
    }

    @Override
    public long getConfig()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property config not supported in version 1.5");
    }

    @Override
    public long getMaxEntries() {
        return maxEntries;
    }

    @Override
    public List<OFTableFeatureProp> getProperties() {
        return properties;
    }

    @Override
    public OFTableFeaturesCommand getCommand() {
        return command;
    }

    @Override
    public Set<OFTableFeatureFlag> getFeatures() {
        return features;
    }

    @Override
    public Set<OFTableConfig> getCapabilities() {
        return capabilities;
    }

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



    public OFTableFeatures.Builder createBuilder() {
        return new BuilderWithParent(this);
    }

    static class BuilderWithParent implements OFTableFeatures.Builder {
        final OFTableFeaturesVer15 parentMessage;

        // OF message fields
        private boolean tableIdSet;
        private TableId tableId;
        private boolean commandSet;
        private OFTableFeaturesCommand command;
        private boolean featuresSet;
        private Set<OFTableFeatureFlag> features;
        private boolean nameSet;
        private String name;
        private boolean metadataMatchSet;
        private U64 metadataMatch;
        private boolean metadataWriteSet;
        private U64 metadataWrite;
        private boolean capabilitiesSet;
        private Set<OFTableConfig> capabilities;
        private boolean maxEntriesSet;
        private long maxEntries;
        private boolean propertiesSet;
        private List<OFTableFeatureProp> properties;

        BuilderWithParent(OFTableFeaturesVer15 parentMessage) {
            this.parentMessage = parentMessage;
        }

    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFTableFeatures.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public String getName() {
        return name;
    }

    @Override
    public OFTableFeatures.Builder setName(String name) {
        this.name = name;
        this.nameSet = true;
        return this;
    }
    @Override
    public U64 getMetadataMatch() {
        return metadataMatch;
    }

    @Override
    public OFTableFeatures.Builder setMetadataMatch(U64 metadataMatch) {
        this.metadataMatch = metadataMatch;
        this.metadataMatchSet = true;
        return this;
    }
    @Override
    public U64 getMetadataWrite() {
        return metadataWrite;
    }

    @Override
    public OFTableFeatures.Builder setMetadataWrite(U64 metadataWrite) {
        this.metadataWrite = metadataWrite;
        this.metadataWriteSet = true;
        return this;
    }
    @Override
    public long getConfig()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property config not supported in version 1.5");
    }

    @Override
    public OFTableFeatures.Builder setConfig(long config) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property config not supported in version 1.5");
    }
    @Override
    public long getMaxEntries() {
        return maxEntries;
    }

    @Override
    public OFTableFeatures.Builder setMaxEntries(long maxEntries) {
        this.maxEntries = maxEntries;
        this.maxEntriesSet = true;
        return this;
    }
    @Override
    public List<OFTableFeatureProp> getProperties() {
        return properties;
    }

    @Override
    public OFTableFeatures.Builder setProperties(List<OFTableFeatureProp> properties) {
        this.properties = properties;
        this.propertiesSet = true;
        return this;
    }
    @Override
    public OFTableFeaturesCommand getCommand() {
        return command;
    }

    @Override
    public OFTableFeatures.Builder setCommand(OFTableFeaturesCommand command) {
        this.command = command;
        this.commandSet = true;
        return this;
    }
    @Override
    public Set<OFTableFeatureFlag> getFeatures() {
        return features;
    }

    @Override
    public OFTableFeatures.Builder setFeatures(Set<OFTableFeatureFlag> features) {
        this.features = features;
        this.featuresSet = true;
        return this;
    }
    @Override
    public Set<OFTableConfig> getCapabilities() {
        return capabilities;
    }

    @Override
    public OFTableFeatures.Builder setCapabilities(Set<OFTableConfig> capabilities) {
        this.capabilities = capabilities;
        this.capabilitiesSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }



        @Override
        public OFTableFeatures build() {
                TableId tableId = this.tableIdSet ? this.tableId : parentMessage.tableId;
                if(tableId == null)
                    throw new NullPointerException("Property tableId must not be null");
                OFTableFeaturesCommand command = this.commandSet ? this.command : parentMessage.command;
                if(command == null)
                    throw new NullPointerException("Property command must not be null");
                Set<OFTableFeatureFlag> features = this.featuresSet ? this.features : parentMessage.features;
                if(features == null)
                    throw new NullPointerException("Property features must not be null");
                String name = this.nameSet ? this.name : parentMessage.name;
                if(name == null)
                    throw new NullPointerException("Property name must not be null");
                U64 metadataMatch = this.metadataMatchSet ? this.metadataMatch : parentMessage.metadataMatch;
                if(metadataMatch == null)
                    throw new NullPointerException("Property metadataMatch must not be null");
                U64 metadataWrite = this.metadataWriteSet ? this.metadataWrite : parentMessage.metadataWrite;
                if(metadataWrite == null)
                    throw new NullPointerException("Property metadataWrite must not be null");
                Set<OFTableConfig> capabilities = this.capabilitiesSet ? this.capabilities : parentMessage.capabilities;
                if(capabilities == null)
                    throw new NullPointerException("Property capabilities must not be null");
                long maxEntries = this.maxEntriesSet ? this.maxEntries : parentMessage.maxEntries;
                List<OFTableFeatureProp> properties = this.propertiesSet ? this.properties : parentMessage.properties;
                if(properties == null)
                    throw new NullPointerException("Property properties must not be null");

                //
                return new OFTableFeaturesVer15(
                    tableId,
                    command,
                    features,
                    name,
                    metadataMatch,
                    metadataWrite,
                    capabilities,
                    maxEntries,
                    properties
                );
        }

    }

    static class Builder implements OFTableFeatures.Builder {
        // OF message fields
        private boolean tableIdSet;
        private TableId tableId;
        private boolean commandSet;
        private OFTableFeaturesCommand command;
        private boolean featuresSet;
        private Set<OFTableFeatureFlag> features;
        private boolean nameSet;
        private String name;
        private boolean metadataMatchSet;
        private U64 metadataMatch;
        private boolean metadataWriteSet;
        private U64 metadataWrite;
        private boolean capabilitiesSet;
        private Set<OFTableConfig> capabilities;
        private boolean maxEntriesSet;
        private long maxEntries;
        private boolean propertiesSet;
        private List<OFTableFeatureProp> properties;

    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public OFTableFeatures.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }
    @Override
    public String getName() {
        return name;
    }

    @Override
    public OFTableFeatures.Builder setName(String name) {
        this.name = name;
        this.nameSet = true;
        return this;
    }
    @Override
    public U64 getMetadataMatch() {
        return metadataMatch;
    }

    @Override
    public OFTableFeatures.Builder setMetadataMatch(U64 metadataMatch) {
        this.metadataMatch = metadataMatch;
        this.metadataMatchSet = true;
        return this;
    }
    @Override
    public U64 getMetadataWrite() {
        return metadataWrite;
    }

    @Override
    public OFTableFeatures.Builder setMetadataWrite(U64 metadataWrite) {
        this.metadataWrite = metadataWrite;
        this.metadataWriteSet = true;
        return this;
    }
    @Override
    public long getConfig()throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Property config not supported in version 1.5");
    }

    @Override
    public OFTableFeatures.Builder setConfig(long config) throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Property config not supported in version 1.5");
    }
    @Override
    public long getMaxEntries() {
        return maxEntries;
    }

    @Override
    public OFTableFeatures.Builder setMaxEntries(long maxEntries) {
        this.maxEntries = maxEntries;
        this.maxEntriesSet = true;
        return this;
    }
    @Override
    public List<OFTableFeatureProp> getProperties() {
        return properties;
    }

    @Override
    public OFTableFeatures.Builder setProperties(List<OFTableFeatureProp> properties) {
        this.properties = properties;
        this.propertiesSet = true;
        return this;
    }
    @Override
    public OFTableFeaturesCommand getCommand() {
        return command;
    }

    @Override
    public OFTableFeatures.Builder setCommand(OFTableFeaturesCommand command) {
        this.command = command;
        this.commandSet = true;
        return this;
    }
    @Override
    public Set<OFTableFeatureFlag> getFeatures() {
        return features;
    }

    @Override
    public OFTableFeatures.Builder setFeatures(Set<OFTableFeatureFlag> features) {
        this.features = features;
        this.featuresSet = true;
        return this;
    }
    @Override
    public Set<OFTableConfig> getCapabilities() {
        return capabilities;
    }

    @Override
    public OFTableFeatures.Builder setCapabilities(Set<OFTableConfig> capabilities) {
        this.capabilities = capabilities;
        this.capabilitiesSet = true;
        return this;
    }
    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_15;
    }

//
        @Override
        public OFTableFeatures build() {
            TableId tableId = this.tableIdSet ? this.tableId : DEFAULT_TABLE_ID;
            if(tableId == null)
                throw new NullPointerException("Property tableId must not be null");
            if(!this.commandSet)
                throw new IllegalStateException("Property command doesn't have default value -- must be set");
            if(command == null)
                throw new NullPointerException("Property command must not be null");
            Set<OFTableFeatureFlag> features = this.featuresSet ? this.features : DEFAULT_FEATURES;
            if(features == null)
                throw new NullPointerException("Property features must not be null");
            String name = this.nameSet ? this.name : DEFAULT_NAME;
            if(name == null)
                throw new NullPointerException("Property name must not be null");
            U64 metadataMatch = this.metadataMatchSet ? this.metadataMatch : DEFAULT_METADATA_MATCH;
            if(metadataMatch == null)
                throw new NullPointerException("Property metadataMatch must not be null");
            U64 metadataWrite = this.metadataWriteSet ? this.metadataWrite : DEFAULT_METADATA_WRITE;
            if(metadataWrite == null)
                throw new NullPointerException("Property metadataWrite must not be null");
            Set<OFTableConfig> capabilities = this.capabilitiesSet ? this.capabilities : DEFAULT_CAPABILITIES;
            if(capabilities == null)
                throw new NullPointerException("Property capabilities must not be null");
            long maxEntries = this.maxEntriesSet ? this.maxEntries : DEFAULT_MAX_ENTRIES;
            List<OFTableFeatureProp> properties = this.propertiesSet ? this.properties : DEFAULT_PROPERTIES;
            if(properties == null)
                throw new NullPointerException("Property properties must not be null");


            return new OFTableFeaturesVer15(
                    tableId,
                    command,
                    features,
                    name,
                    metadataMatch,
                    metadataWrite,
                    capabilities,
                    maxEntries,
                    properties
                );
        }

    }


    final static Reader READER = new Reader();
    static class Reader implements OFMessageReader<OFTableFeatures> {
        @Override
        public OFTableFeatures readFrom(ByteBuf bb) throws OFParseError {
            int start = bb.readerIndex();
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
            TableId tableId = TableId.readByte(bb);
            OFTableFeaturesCommand command = OFTableFeaturesCommandSerializerVer15.readFrom(bb);
            Set<OFTableFeatureFlag> features = OFTableFeatureFlagSerializerVer15.readFrom(bb);
            String name = ChannelUtils.readFixedLengthString(bb, 32);
            U64 metadataMatch = U64.ofRaw(bb.readLong());
            U64 metadataWrite = U64.ofRaw(bb.readLong());
            Set<OFTableConfig> capabilities = OFTableConfigSerializerVer15.readFrom(bb);
            long maxEntries = U32.f(bb.readInt());
            List<OFTableFeatureProp> properties = ChannelUtils.readList(bb, length - (bb.readerIndex() - start), OFTableFeaturePropVer15.READER);

            OFTableFeaturesVer15 tableFeaturesVer15 = new OFTableFeaturesVer15(
                    tableId,
                      command,
                      features,
                      name,
                      metadataMatch,
                      metadataWrite,
                      capabilities,
                      maxEntries,
                      properties
                    );
            if(logger.isTraceEnabled())
                logger.trace("readFrom - read={}", tableFeaturesVer15);
            return tableFeaturesVer15;
        }
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static OFTableFeaturesVer15Funnel FUNNEL = new OFTableFeaturesVer15Funnel();
    static class OFTableFeaturesVer15Funnel implements Funnel<OFTableFeaturesVer15> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(OFTableFeaturesVer15 message, PrimitiveSink sink) {
            // FIXME: skip funnel of length
            message.tableId.putTo(sink);
            OFTableFeaturesCommandSerializerVer15.putTo(message.command, sink);
            OFTableFeatureFlagSerializerVer15.putTo(message.features, sink);
            sink.putUnencodedChars(message.name);
            message.metadataMatch.putTo(sink);
            message.metadataWrite.putTo(sink);
            OFTableConfigSerializerVer15.putTo(message.capabilities, sink);
            sink.putLong(message.maxEntries);
            FunnelUtils.putList(message.properties, sink);
        }
    }


    public void writeTo(ByteBuf bb) {
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<OFTableFeaturesVer15> {
        @Override
        public void write(ByteBuf bb, OFTableFeaturesVer15 message) {
            int startIndex = bb.writerIndex();
            // length is length of variable message, will be updated at the end
            int lengthIndex = bb.writerIndex();
            bb.writeShort(U16.t(0));

            message.tableId.writeByte(bb);
            OFTableFeaturesCommandSerializerVer15.writeTo(bb, message.command);
            OFTableFeatureFlagSerializerVer15.writeTo(bb, message.features);
            ChannelUtils.writeFixedLengthString(bb, message.name, 32);
            bb.writeLong(message.metadataMatch.getValue());
            bb.writeLong(message.metadataWrite.getValue());
            OFTableConfigSerializerVer15.writeTo(bb, message.capabilities);
            bb.writeInt(U32.t(message.maxEntries));
            ChannelUtils.writeList(bb, message.properties);

            // update length field
            int length = bb.writerIndex() - startIndex;
            if (length > MAXIMUM_LENGTH) {
                throw new IllegalArgumentException("OFTableFeaturesVer15: message length (" + length + ") exceeds maximum (0xFFFF)");
            }
            bb.setShort(lengthIndex, length);

        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("OFTableFeaturesVer15(");
        b.append("tableId=").append(tableId);
        b.append(", ");
        b.append("command=").append(command);
        b.append(", ");
        b.append("features=").append(features);
        b.append(", ");
        b.append("name=").append(name);
        b.append(", ");
        b.append("metadataMatch=").append(metadataMatch);
        b.append(", ");
        b.append("metadataWrite=").append(metadataWrite);
        b.append(", ");
        b.append("capabilities=").append(capabilities);
        b.append(", ");
        b.append("maxEntries=").append(maxEntries);
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
        OFTableFeaturesVer15 other = (OFTableFeaturesVer15) obj;

        if (tableId == null) {
            if (other.tableId != null)
                return false;
        } else if (!tableId.equals(other.tableId))
            return false;
        if (command == null) {
            if (other.command != null)
                return false;
        } else if (!command.equals(other.command))
            return false;
        if (features == null) {
            if (other.features != null)
                return false;
        } else if (!features.equals(other.features))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (metadataMatch == null) {
            if (other.metadataMatch != null)
                return false;
        } else if (!metadataMatch.equals(other.metadataMatch))
            return false;
        if (metadataWrite == null) {
            if (other.metadataWrite != null)
                return false;
        } else if (!metadataWrite.equals(other.metadataWrite))
            return false;
        if (capabilities == null) {
            if (other.capabilities != null)
                return false;
        } else if (!capabilities.equals(other.capabilities))
            return false;
        if( maxEntries != other.maxEntries)
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

        result = prime * result + ((tableId == null) ? 0 : tableId.hashCode());
        result = prime * result + ((command == null) ? 0 : command.hashCode());
        result = prime * result + ((features == null) ? 0 : features.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((metadataMatch == null) ? 0 : metadataMatch.hashCode());
        result = prime * result + ((metadataWrite == null) ? 0 : metadataWrite.hashCode());
        result = prime * result + ((capabilities == null) ? 0 : capabilities.hashCode());
        result = prime *  (int) (maxEntries ^ (maxEntries >>> 32));
        result = prime * result + ((properties == null) ? 0 : properties.hashCode());
        return result;
    }

}
