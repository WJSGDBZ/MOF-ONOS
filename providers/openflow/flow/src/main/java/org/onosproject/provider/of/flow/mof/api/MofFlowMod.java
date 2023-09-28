package org.onosproject.provider.of.flow.mof.api;

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
import org.onosproject.provider.of.flow.mof.impl.MofFlowAddImpl;

import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
public interface MofFlowMod extends OFObject, OFMessage {

    OFVersion getVersion();
    OFType getType();
    long getXid();
    TrafficSelector getSelector();
    Match getMatch();

    U64 getCookie();
    OFFlowModCommand getCommand();
    int getIdleTimeout();
    int getHardTimeout();
    int getPriority();
    OFBufferId getBufferId();
    OFPort getOutPort();
    Set<OFFlowModFlags> getFlags();
    TrafficTreatment getTreatment();

    void writeTo(ByteBuf bb);

    Builder createBuilder();

    public interface Builder extends OFMessage.Builder {
        MofFlowMod build();
        // MofFlowMod mofbuild();
        OFVersion getVersion();
        OFType getType();
        long getXid();
        Builder setXid(long xid);

        TableId getTableId();
        Builder setTableId(TableId tableId);
        TrafficSelector getSelector();
        Match getMatch();
        Builder setMatch(Match match);
        Builder setSelector(TrafficSelector selector);
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
        TrafficTreatment getTreatment();
        Builder setTreatment(TrafficTreatment treatment);
        List<OFAction> getActions() throws UnsupportedOperationException;
        Builder setActions(List<OFAction> actions) throws UnsupportedOperationException;
    }
}