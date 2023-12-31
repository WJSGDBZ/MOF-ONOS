// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
// Copyright (c) 2011, 2012 Open Networking Foundation
// Copyright (c) 2012, 2013 Big Switch Networks, Inc.
// This library was generated by the LoxiGen Compiler.
// See the file LICENSE.txt which should have been included in the source distribution

// Automatically generated by LOXI from template of_interface.java
// Do not modify

package org.projectfloodlight.openflow.protocol;

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
import java.util.Set;
import java.util.List;
import io.netty.buffer.ByteBuf;

public interface OFFeaturesReply extends OFObject, OFMessage {
    OFVersion getVersion();
    OFType getType();
    long getXid();
    DatapathId getDatapathId();
    long getNBuffers();
    short getNTables();
    Set<OFCapabilities> getCapabilities();
    Set<OFActionType> getActions() throws UnsupportedOperationException;
    List<OFPortDesc> getPorts() throws UnsupportedOperationException;
    long getReserved() throws UnsupportedOperationException;
    OFAuxId getAuxiliaryId() throws UnsupportedOperationException;

    void writeTo(ByteBuf channelBuffer);

    Builder createBuilder();
    public interface Builder extends OFMessage.Builder {
        OFFeaturesReply build();
        OFVersion getVersion();
        OFType getType();
        long getXid();
        Builder setXid(long xid);
        DatapathId getDatapathId();
        Builder setDatapathId(DatapathId datapathId);
        long getNBuffers();
        Builder setNBuffers(long nBuffers);
        short getNTables();
        Builder setNTables(short nTables);
        Set<OFCapabilities> getCapabilities();
        Builder setCapabilities(Set<OFCapabilities> capabilities);
        Set<OFActionType> getActions() throws UnsupportedOperationException;
        Builder setActions(Set<OFActionType> actions) throws UnsupportedOperationException;
        List<OFPortDesc> getPorts() throws UnsupportedOperationException;
        Builder setPorts(List<OFPortDesc> ports) throws UnsupportedOperationException;
        long getReserved() throws UnsupportedOperationException;
        Builder setReserved(long reserved) throws UnsupportedOperationException;
        OFAuxId getAuxiliaryId() throws UnsupportedOperationException;
        Builder setAuxiliaryId(OFAuxId auxiliaryId) throws UnsupportedOperationException;
    }
}
