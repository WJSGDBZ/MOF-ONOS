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
import io.netty.buffer.ByteBuf;

public interface OFBsnVportL2Gre extends OFObject, OFBsnVport {
    int getType();
    Set<OFBsnVportL2GreFlags> getFlags();
    OFPort getPortNo();
    OFPort getLoopbackPortNo();
    MacAddress getLocalMac();
    MacAddress getNhMac();
    IPv4Address getSrcIp();
    IPv4Address getDstIp();
    short getDscp();
    short getTtl();
    long getVpn();
    long getRateLimit();
    String getIfName();
    OFVersion getVersion();

    void writeTo(ByteBuf channelBuffer);

    Builder createBuilder();
    public interface Builder extends OFBsnVport.Builder {
        OFBsnVportL2Gre build();
        int getType();
        Set<OFBsnVportL2GreFlags> getFlags();
        Builder setFlags(Set<OFBsnVportL2GreFlags> flags);
        OFPort getPortNo();
        Builder setPortNo(OFPort portNo);
        OFPort getLoopbackPortNo();
        Builder setLoopbackPortNo(OFPort loopbackPortNo);
        MacAddress getLocalMac();
        Builder setLocalMac(MacAddress localMac);
        MacAddress getNhMac();
        Builder setNhMac(MacAddress nhMac);
        IPv4Address getSrcIp();
        Builder setSrcIp(IPv4Address srcIp);
        IPv4Address getDstIp();
        Builder setDstIp(IPv4Address dstIp);
        short getDscp();
        Builder setDscp(short dscp);
        short getTtl();
        Builder setTtl(short ttl);
        long getVpn();
        Builder setVpn(long vpn);
        long getRateLimit();
        Builder setRateLimit(long rateLimit);
        String getIfName();
        Builder setIfName(String ifName);
        OFVersion getVersion();
    }
}
