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
import java.util.List;
import java.util.Set;
import io.netty.buffer.ByteBuf;

import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;

public interface MofFlowStatsEntry extends OFObject {
    TableId getTableId();

    TrafficSelector getMatch();

    long getDurationSec() throws UnsupportedOperationException;

    long getDurationNsec() throws UnsupportedOperationException;

    int getPriority();

    int getIdleTimeout();

    int getHardTimeout();

    U64 getCookie();

    U64 getPacketCount() throws UnsupportedOperationException;

    U64 getByteCount() throws UnsupportedOperationException;

    TrafficTreatment getActions() throws UnsupportedOperationException;

    List<OFInstruction> getInstructions() throws UnsupportedOperationException;

    Set<OFFlowModFlags> getFlags() throws UnsupportedOperationException;

    int getImportance() throws UnsupportedOperationException;

    Stat getStats() throws UnsupportedOperationException;

    OFVersion getVersion();

    void writeTo(ByteBuf channelBuffer);

    Builder createBuilder();

    public interface Builder {
        MofFlowStatsEntry build();

        TableId getTableId();

        Builder setTableId(TableId tableId);

        TrafficSelector getMatch();

        Builder setMatch(TrafficSelector match);

        long getDurationSec() throws UnsupportedOperationException;

        Builder setDurationSec(long durationSec) throws UnsupportedOperationException;

        long getDurationNsec() throws UnsupportedOperationException;

        Builder setDurationNsec(long durationNsec) throws UnsupportedOperationException;

        int getPriority();

        Builder setPriority(int priority);

        int getIdleTimeout();

        Builder setIdleTimeout(int idleTimeout);

        int getHardTimeout();

        Builder setHardTimeout(int hardTimeout);

        U64 getCookie();

        Builder setCookie(U64 cookie);

        U64 getPacketCount() throws UnsupportedOperationException;

        Builder setPacketCount(U64 packetCount) throws UnsupportedOperationException;

        U64 getByteCount() throws UnsupportedOperationException;

        Builder setByteCount(U64 byteCount) throws UnsupportedOperationException;

        TrafficTreatment getActions() throws UnsupportedOperationException;

        Builder setActions(TrafficTreatment actions) throws UnsupportedOperationException;

        List<OFInstruction> getInstructions() throws UnsupportedOperationException;

        Builder setInstructions(List<OFInstruction> instructions) throws UnsupportedOperationException;

        Set<OFFlowModFlags> getFlags() throws UnsupportedOperationException;

        Builder setFlags(Set<OFFlowModFlags> flags) throws UnsupportedOperationException;

        int getImportance() throws UnsupportedOperationException;

        Builder setImportance(int importance) throws UnsupportedOperationException;

        Stat getStats() throws UnsupportedOperationException;

        Builder setStats(Stat stats) throws UnsupportedOperationException;

        OFVersion getVersion();
    }
}