package org.onosproject.openflow.controller.mof.impl;

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
import org.onosproject.openflow.controller.impl.OFMessageDecoder;
import org.onosproject.openflow.controller.mof.impl.MofStatsReplyImpl;

import org.projectfloodlight.openflow.exceptions.*;
import io.netty.buffer.ByteBuf;
import java.util.Set;
import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;

public class MofMessageImpl {
    private static final Logger log = getLogger(MofMessageImpl.class);
    // version: 1.0
    final static byte WIRE_VERSION = 1;
    final static int MINIMUM_LENGTH = 8;

    public final static MofMessageImpl.Reader READER = new Reader();

    public static class Reader implements OFMessageReader<OFMessage> {
        @Override
        public OFMessage readFrom(ByteBuf bb) throws OFParseError {
            if (bb.readableBytes() < MINIMUM_LENGTH)
                return null;
            int start = bb.readerIndex();
            // fixed value property version == 1
            byte version = bb.readByte();
            if (version != (byte) 0x1)
                return null;

            byte type = bb.readByte();
            bb.readerIndex(start);
            switch (type) {
                case (byte)253:
                    log.info("receive MOF_STATS_REPLY message!");
                    // discriminator value OFType.STATS_REPLY=83 for class OFStatsReplyVer10
                    return MofStatsReplyImpl.READER.readFrom(bb);
                case (byte)17:
                case (byte)2 : // heart beat message
                    return null;
                default:
                    log.info("receive message type = {}, in turn to normal message", type);
                    return null;
            }
        }
    }

}