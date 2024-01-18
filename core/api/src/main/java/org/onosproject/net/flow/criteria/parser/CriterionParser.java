package org.onosproject.net.flow.criteria.parser;

import org.onosproject.net.flow.criteria.Criterion.Type;;

public final class CriterionParser {
    
    final static String PREFIX = "0x";
    //parser 1, 2, 4 bytes 
    public static String BasicParser(long data, long mask, Type type) {
        switch(type){
        case DL_TYPE:
            return PREFIX + Long.toHexString(data);
        case IN_PORT:
            return data + "";
        case VLAN1_TPID:
        case VLAN1_QID:
        case VLAN2_TPID:
        case VLAN2_QID:
        case VER_HL_E:
        case TOS_E:
        case TOT_LEN_E:
        case IP_ID_E:
        case FRAG_OFF_E:
        case TTL_E:
        case IPV4_E_TYPE:
        case IP_CHECK_E:
        case IP_SADDR_E:
        case IP_DADDR_E:
        case IPV6_VER_TP_FLB_E:
        case IPV6_PLEN_E:
        case IPV6_E_TYPE:
        case IPV6_HLMT_E:
        case TCP_SOURCE:
        case TCP_DEST:
        case SEQ:
        case ACK_SEQ:
        case OFF_BITS:
        case WINDOW:
        case TCP_CHECK:
        case URG_PTR:
        case UDP_SOURCE:
        case UDP_DEST:
        case LEN:
        case UDP_CHECK:
        case SRV6_TYPE:
        case SRV6_HDR_EXT_LEN:
        case SRV6_ROUTING_TYPE:
        case SRV6_SEGMENTS_LEFT:
        case SRV6_LAST_ENTY:
        case SRV6_FLAGS:
        case SRV6_TAG:
        case IPV6_VER_TP_FLB_I:
        case IPV6_PLEN_I:
        case IPV6_I_TYPE:
        case IPV6_HLMT_I:
        case VER_HL_I:
        case TOS_I:
        case TOT_LEN_I:
        case IP_ID_I:
        case FRAG_OFF_I:
        case TTL_I:
        case IPV4_I_TYPE:
        case IP_CHECK_I:
        case IP_SADDR_I:
        case IP_DADDR_I:
        default:
            return PREFIX + Long.toHexString(data) + "/" + PREFIX + Long.toHexString(mask).toUpperCase();
        }
    }

    // others 
    public static String ComplexParser(byte[] data, byte[] mask, Type type) {
        switch(type){
        case MAC_DST:
            return encodeMACStringHelper(data, mask);
        case MAC_SRC:
            return encodeMACStringHelper(data, mask);
        case IPV6_SRC_E:
        case IPV6_DST_E:
        case SRV6_SEGMENTLIST3:
        case SRV6_SEGMENTLIST2:
        case SRV6_SEGMENTLIST1:
        case IPV6_SRC_I:
        case IPV6_DST_I:
        default:
            return PREFIX + encodeHexStringHelper(data) + "/" + PREFIX + encodeHexStringHelper(mask);
        }
    }

    /*****************************************************************************
     * Parser Helper Function
     *****************************************************************************/

    /**
     * Parser hepler function
     * @input  byte[] data
     * @return Hex format String of data
     */
    public static String encodeHexStringHelper(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Parser hepler function
     * @input  byte[] data : ipv6 Address
     *         byte[] mask : ipv6 Mask Address
     * @return customer-friendly IPV6 Fromat String
     */
    public static String encodeIPV6StringHelper(byte[] data, byte[] mask) {
        String[] result = new String[2];

        // Convert IP bytes to IPv6 string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            sb.append(String.format("%02X%02X", data[i], data[i + 1]));
            if (i < 14) {
                sb.append(":");
            }
        }
        result[0] = sb.toString();
    
        // Convert mask bytes to prefix length
        int prefixLength = 0;
        for (byte b : mask) {
            for (int i = 7; i >= 0; i--) {
                if ((b & (1 << i)) != 0) {
                    prefixLength++;
                } else {
                    break;
                }
            }
        }
        result[1] = "/" + prefixLength;
    
        return result[0] + result[1];
    }

    /**
     * Parser hepler function
     * @input  int data : ipv4 Address
     *         int mask : ipv4 Mask Address
     * @return customer-friendly IPV4 Fromat String
     */
    public static String encodeIPV4StringHelper(long data, long mask) {
        String[] result = new String[2];
        result[0] = String.format("%d.%d.%d.%d", (data >> 24) & 0xFF, (data >> 16) & 0xFF, (data >> 8) & 0xFF, data & 0xFF);

        int bits = 0;
        for (int i = 31; i >= 0; i--) {
            if ((mask & (1L << i)) != 0) {
                bits++;
            } else {
                break;
            }
        }
        result[1] = "/" + bits;

        return result[0] + result[1];
    }

    /**
     * Parser hepler function
     * @input  byte[] data : MAC Address
     *         byte[] mask : MAC Mask Address
     * @return customer-friendly MAC Fromat String
     */
    public static String encodeMACStringHelper(byte[] data, byte[] mask) {
        String address = String.format("%02X:%02X:%02X:%02X:%02X:%02X", 
                            data[0], data[1], data[2], data[3], data[4], data[5]);

        int bits = 0;
        for (byte b : mask) {
            for (int i = 7; i >= 0; i--) {
                if ((b & (1 << i)) != 0) {
                    bits++;
                } else {
                    break;
                }
            }
        }

        return address + "/" + bits;
    }
}

