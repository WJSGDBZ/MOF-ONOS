package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import java.util.Set;

import io.netty.buffer.Unpooled;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.packet.mof.*;

public class Specific_Protocol {
    private static Specific_Protocol instance = new Specific_Protocol();
    private Set<Integer> white_list = Set.of(0x12);

    public static synchronized Specific_Protocol getInstance(){
        return instance;
    }

    public boolean contains(int type){
        return white_list.contains(type);
    }
    public void parse_specific_protocolL3(int type, ByteBuf bb, MOFL3Layer l3){
        throw new UnsupportedOperationException("L3Layer has no specific protocol yet");
    }

    public void parse_specific_protocolL4(int type, ByteBuf bb, MOFL4Layer l4){
        switch (type) {
            case 0x12:
                int start = bb.readerIndex();
                bb.skipBytes(1);
                int hdr_ext_len = bb.readByte();
                bb.readerIndex(start);

                switch (hdr_ext_len) {
                    case 1: l4.setSrv6_1_Protocol(Srv6_1_Protocol.read(bb));
                        break;
                    case 2: l4.setSrv6_2_Protocol(Srv6_2_Protocol.read(bb));
                        break;
                    case 3: l4.setSrv6_3_Protocol(Srv6_3_Protocol.read(bb));
                        break;
                    default:
                        throw new UnsupportedOperationException("L4Layer type is unsupported");
                }
                break;
            default:
                break;
        }
    }

    public void parse_specific_protocolL5(int type, ByteBuf bb, MOFL5Layer l5){
        throw new UnsupportedOperationException("L5Layer has no specific protocol yet");
    }

}