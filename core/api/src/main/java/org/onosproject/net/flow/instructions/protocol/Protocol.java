package org.onosproject.net.flow.instructions.protocol;

import io.netty.buffer.ByteBuf;

public interface Protocol {
    final int UNKNOW = 0;
    final int MAC = 1 << 0;
    final int VLAN1 = 1 << 1;
    final int VLAN2 = 1 << 2;
    final int DL = 1 << 3;
    final int IPV4_E = 1 << 4;
    final int IPV6_E = 1 << 5;
    final int UDP = 1 << 6;
    final int SRV6_1 = 1 << 7;
    final int SRV6_2 = 1 << 8;
    final int SRV6_3 = 1 << 9;
    final int IPV6_I = 1 << 10;

    public static String ProtocolFormatByType(int type) {
        switch(type){
            case MAC:
                return "MAC_PROTOCOL";
            case VLAN1:
                return "VLAN1_PROTOCOL";
            case VLAN2:
                return "VLAN2_PROTOCOL";
            case DL:
                return "DL_PROTOCOL";
            case IPV4_E:
                return "IPV4_E_PROTOCOL";
            case IPV6_E:
                return "IPV6_E_PROTOCOL";
            case UDP:
                return "UDP_PROTOCOL";
            case SRV6_1:
                return "SRV6_1_PROTOCOL";
            case SRV6_2:
                return "SRV6_2_PROTOCOL";
            case SRV6_3:
                return "SRV6_3_PROTOCOL";
            case IPV6_I:
                return "IPV6_I_PROTOCOL";
            default:
                return "UNKONW_PROTOCOL";
        }
    }

    public static int ProtocolFormatByString(String type) {
        switch(type){
            case "MAC_PROTOCOL":
                return MAC;
            case "VLAN1_PROTOCOL":
                return VLAN1;
            case "VLAN2_PROTOCOL":
                return VLAN2;
            case "DL_PROTOCOL":
                return DL;
            case "IPV4_E_PROTOCOL":
                return IPV4_E;
            case "IPV6_E_PROTOCOL":
                return IPV6_E;
            case "UDP_PROTOCOL":
                return UDP;
            case "SRV6_1_PROTOCOL":
                return SRV6_1;
            case "SRV6_2_PROTOCOL":
                return SRV6_2;
            case "SRV6_3_PROTOCOL":
                return SRV6_3;
            case "IPV6_I_PROTOCOL":
                return IPV6_I;
            default:
                return UNKNOW;
        }
    }

    void write(ByteBuf bb);
    void writeMask(ByteBuf bb);
}