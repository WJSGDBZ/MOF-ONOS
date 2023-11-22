/*
 * Copyright 2015-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.openflow.controller.impl;


import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;

import static org.slf4j.LoggerFactory.getLogger;

import java.util.List;
import io.netty.buffer.ByteBuf;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFMessageReader;
import org.onosproject.openflow.controller.mof.impl.*;
import org.projectfloodlight.openflow.exceptions.*;
import org.slf4j.Logger;

/**
 * Decode an openflow message from a netty channel, for use in a netty pipeline.
 */
public final class OFMessageDecoder extends ByteToMessageDecoder {

    private static final Logger log = getLogger(OFMessageDecoder.class);
    final static int MINIMUM_LENGTH = 8;
    final static int STATS_REPLY_MINIMUM_LENGTH = 12;

    public static OFMessageDecoder getInstance() {
        // not Sharable
        return new OFMessageDecoder();
    }

    private OFMessageDecoder() {}

    private OFMessage processMofMessage(ByteBuf bb, OFMessageReader<OFMessage> reader) throws Exception {
        OFMessage message = null;
        if(!bb.isReadable())
            return null; // Do Nothing;

        if(bb.readableBytes() < MINIMUM_LENGTH)
            return null; 

        int start = bb.readerIndex();
        // fixed value property version == 1
        byte version = bb.readByte();
        if (version != (byte) 0x1){
            bb.readerIndex(start);
            return reader.readFrom(bb);
            //throw new OFParseError("only support openflow 1.0 now is openflow 1." + (version-1));
        }
            

        byte type = bb.readByte();
        // bb.readerIndex(start);
        switch (type) {
            case (byte)253:
                log.info("receive MOF_STATS_REPLY message!");
                if (bb.readableBytes() < STATS_REPLY_MINIMUM_LENGTH){
                    bb.readerIndex(start);
                    return null;
                }
                    
                int length = bb.readShort() & 0xFFFF;
                if (length < STATS_REPLY_MINIMUM_LENGTH)
                    throw new OFParseError("Wrong length: Expected to be >= " + STATS_REPLY_MINIMUM_LENGTH + ", was: " + length);

                bb.readInt();

                short statsType = bb.readShort();
                bb.readerIndex(start);
                switch (statsType) {
                    case (short) 0x1:
                        // discriminator value OFStatsType.FLOW=1 for class OFFlowStatsReplyVer10
                        log.info("receive MOF_FLOW_STATS_REPLY message!");
                        message = MofFlowStatsReplyImpl.READER.readFrom(bb);
                        break;
                    default:
                        message = reader.readFrom(bb);
                }
                break;
            default:
                bb.readerIndex(start);
                //log.info("receive message type = {}, in turn to normal message", type);
                message = reader.readFrom(bb);
        }

        return message;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx,
                          ByteBuf byteBuf,
                          List<Object> out) throws Exception {

        if (!ctx.channel().isActive()) {
            // In testing, I see decode being called AFTER decode last.
            // This check avoids that from reading corrupted frames
            return;
        }
        //log.info("decode OFMessage");
        // Note that a single call to readFrom results in reading a single
        // OFMessage from the channel buffer, which is passed on to, and processed
        // by, the controller (in OFChannelHandler).
        // This is different from earlier behavior (with the original openflowj),
        // where we parsed all the messages in the buffer, before passing on
        // a list of the parsed messages to the controller.
        // The performance *may or may not* not be as good as before.
        OFMessageReader<OFMessage> reader = OFFactories.getGenericReader();

        OFMessage message = processMofMessage(byteBuf, reader);
        // if(message == null)
        //     message = reader.readFrom(byteBuf);

        while (message != null) {
            out.add(message);
            message = processMofMessage(byteBuf, reader);
            // if(message == null)
            //     message = reader.readFrom(byteBuf);
        }
    }

}
