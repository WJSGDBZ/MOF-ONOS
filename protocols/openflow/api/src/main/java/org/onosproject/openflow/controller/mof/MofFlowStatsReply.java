package org.onosproject.openflow.controller.mof.api;

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

public interface MofFlowStatsReply extends OFObject, OFStatsReply {
    OFVersion getVersion();

    OFType getType();

    long getXid();

    OFStatsType getStatsType();

    Set<OFStatsReplyFlags> getFlags();

    List<MofFlowStatsEntry> getEntries();

    void writeTo(ByteBuf channelBuffer);

    Builder createBuilder();

    public interface Builder extends OFStatsReply.Builder {
        MofFlowStatsReply build();

        OFVersion getVersion();

        OFType getType();

        long getXid();

        Builder setXid(long xid);

        OFStatsType getStatsType();

        Set<OFStatsReplyFlags> getFlags();

        Builder setFlags(Set<OFStatsReplyFlags> flags);

        List<MofFlowStatsEntry> getEntries();

        Builder setEntries(List<MofFlowStatsEntry> entries);
    }
}