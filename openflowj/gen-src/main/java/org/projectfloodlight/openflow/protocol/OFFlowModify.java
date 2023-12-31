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

public interface OFFlowModify extends OFObject, OFFlowMod {
    OFVersion getVersion();
    OFType getType();
    long getXid();
    Match getMatch();
    U64 getCookie();
    OFFlowModCommand getCommand();
    int getIdleTimeout();
    int getHardTimeout();
    int getPriority();
    OFBufferId getBufferId();
    OFPort getOutPort();
    Set<OFFlowModFlags> getFlags();
    List<OFAction> getActions() throws UnsupportedOperationException;
    U64 getCookieMask() throws UnsupportedOperationException;
    TableId getTableId() throws UnsupportedOperationException;
    OFGroup getOutGroup() throws UnsupportedOperationException;
    List<OFInstruction> getInstructions() throws UnsupportedOperationException;
    int getImportance() throws UnsupportedOperationException;

    void writeTo(ByteBuf channelBuffer);

    Builder createBuilder();
    public interface Builder extends OFFlowMod.Builder {
        OFFlowModify build();
        OFVersion getVersion();
        OFType getType();
        long getXid();
        Builder setXid(long xid);
        Match getMatch();
        Builder setMatch(Match match);
        U64 getCookie();
        Builder setCookie(U64 cookie);
        OFFlowModCommand getCommand();
        int getIdleTimeout();
        Builder setIdleTimeout(int idleTimeout);
        int getHardTimeout();
        Builder setHardTimeout(int hardTimeout);
        int getPriority();
        Builder setPriority(int priority);
        OFBufferId getBufferId();
        Builder setBufferId(OFBufferId bufferId);
        OFPort getOutPort();
        Builder setOutPort(OFPort outPort);
        Set<OFFlowModFlags> getFlags();
        Builder setFlags(Set<OFFlowModFlags> flags);
        List<OFAction> getActions() throws UnsupportedOperationException;
        Builder setActions(List<OFAction> actions) throws UnsupportedOperationException;
        U64 getCookieMask() throws UnsupportedOperationException;
        Builder setCookieMask(U64 cookieMask) throws UnsupportedOperationException;
        TableId getTableId() throws UnsupportedOperationException;
        Builder setTableId(TableId tableId) throws UnsupportedOperationException;
        OFGroup getOutGroup() throws UnsupportedOperationException;
        Builder setOutGroup(OFGroup outGroup) throws UnsupportedOperationException;
        List<OFInstruction> getInstructions() throws UnsupportedOperationException;
        Builder setInstructions(List<OFInstruction> instructions) throws UnsupportedOperationException;
        int getImportance() throws UnsupportedOperationException;
        Builder setImportance(int importance) throws UnsupportedOperationException;
    }
}
