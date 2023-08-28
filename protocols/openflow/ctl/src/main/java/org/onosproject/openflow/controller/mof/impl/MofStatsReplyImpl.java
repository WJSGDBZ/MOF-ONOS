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
import org.projectfloodlight.openflow.exceptions.*;
import io.netty.buffer.ByteBuf;

public class MofStatsReplyImpl {
    // version: 1.0
    final static byte WIRE_VERSION = 1;
    final static int MINIMUM_LENGTH = 12;

    public final static MofStatsReplyImpl.Reader READER = new Reader();

    static class Reader implements OFMessageReader<OFStatsReply> {
        @Override
        public OFStatsReply readFrom(ByteBuf bb) throws OFParseError {
            if (bb.readableBytes() < MINIMUM_LENGTH)
                return null;
            int start = bb.readerIndex();
            // fixed value property version == 1
            byte version = bb.readByte();
            if (version != (byte) 0x1)
                throw new OFParseError("Wrong version: Expected=OFVersion.OF_10(1), got=" + version);
            // fixed value property type == 17
            byte type = bb.readByte();
            if (type != (byte) 0x11)
                throw new OFParseError("Wrong type: Expected=OFType.STATS_REPLY(17), got=" + type);
            int length = U16.f(bb.readShort());
            if (length < MINIMUM_LENGTH)
                throw new OFParseError("Wrong length: Expected to be >= " + MINIMUM_LENGTH + ", was: " + length);
            U32.f(bb.readInt());
            short statsType = bb.readShort();
            bb.readerIndex(start);
            switch (statsType) {
                case (short) 0x1:
                    // discriminator value OFStatsType.FLOW=1 for class OFFlowStatsReplyVer10
                    return MofFlowStatsReplyImpl.READER.readFrom(bb);
                default:
                    return null;
            }
        }
    }
}
