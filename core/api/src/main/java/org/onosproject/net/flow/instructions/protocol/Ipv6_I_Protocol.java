package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Ipv6_Ver_Tp_Flb_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Plen_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_I_TypeCriterion;
import org.onosproject.net.flow.criteria.Ipv6_Hlmt_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Src_ICriterion;
import org.onosproject.net.flow.criteria.Ipv6_Dst_ICriterion;

public class Ipv6_I_Protocol implements Protocol {
    public Ipv6_Ver_Tp_Flb_ICriterion ipv6_ver_tp_flb_i;
    public Ipv6_Plen_ICriterion ipv6_plen_i;
    public Ipv6_I_TypeCriterion ipv6_i_type;
    public Ipv6_Hlmt_ICriterion ipv6_hlmt_i;
    public Ipv6_Src_ICriterion ipv6_src_i;
    public Ipv6_Dst_ICriterion ipv6_dst_i;
    public static int LEN = Ipv6_Ver_Tp_Flb_ICriterion.LEN + Ipv6_Plen_ICriterion.LEN + Ipv6_I_TypeCriterion.LEN + Ipv6_Hlmt_ICriterion.LEN + Ipv6_Src_ICriterion.LEN + Ipv6_Dst_ICriterion.LEN;

    public Ipv6_I_Protocol(Ipv6_Ver_Tp_Flb_ICriterion ipv6_ver_tp_flb_i, Ipv6_Plen_ICriterion ipv6_plen_i, Ipv6_I_TypeCriterion ipv6_i_type, Ipv6_Hlmt_ICriterion ipv6_hlmt_i, Ipv6_Src_ICriterion ipv6_src_i, Ipv6_Dst_ICriterion ipv6_dst_i){
        this.ipv6_ver_tp_flb_i = ipv6_ver_tp_flb_i;
        this.ipv6_plen_i = ipv6_plen_i;
        this.ipv6_i_type = ipv6_i_type;
        this.ipv6_hlmt_i = ipv6_hlmt_i;
        this.ipv6_src_i = ipv6_src_i;
        this.ipv6_dst_i = ipv6_dst_i;
    }

    @Override
    public void write(ByteBuf bb){
        ipv6_ver_tp_flb_i.write(bb);
        ipv6_plen_i.write(bb);
        ipv6_i_type.write(bb);
        ipv6_hlmt_i.write(bb);
        ipv6_src_i.write(bb);
        ipv6_dst_i.write(bb);
        bb.writeZero(16);
    }
  
    @Override
    public void writeMask(ByteBuf bb){
        ipv6_ver_tp_flb_i.writeMask(bb);
        ipv6_plen_i.writeMask(bb);
        ipv6_i_type.writeMask(bb);
        ipv6_hlmt_i.writeMask(bb);
        ipv6_src_i.writeMask(bb);
        ipv6_dst_i.writeMask(bb);
        bb.writeZero(16);
    }
  
    public static Ipv6_I_Protocol read(ByteBuf bb){
        Ipv6_Ver_Tp_Flb_ICriterion ipv6_ver_tp_flb_i = new Ipv6_Ver_Tp_Flb_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_Plen_ICriterion ipv6_plen_i = new Ipv6_Plen_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_I_TypeCriterion ipv6_i_type = new Ipv6_I_TypeCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_Hlmt_ICriterion ipv6_hlmt_i = new Ipv6_Hlmt_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_Src_ICriterion ipv6_src_i = new Ipv6_Src_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_Dst_ICriterion ipv6_dst_i = new Ipv6_Dst_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        bb.skipBytes(16);
        return new Ipv6_I_Protocol(ipv6_ver_tp_flb_i, ipv6_plen_i, ipv6_i_type, ipv6_hlmt_i, ipv6_src_i, ipv6_dst_i);
    }

    @Override
    public String toString() {
        return "Ipv6_I_Protocol{ " + ipv6_ver_tp_flb_i + ", " + ipv6_plen_i + ", " + ipv6_i_type + ", " + ipv6_hlmt_i + ", " + ipv6_src_i + ", " + ipv6_dst_i + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(ipv6_ver_tp_flb_i, ipv6_plen_i, ipv6_i_type, ipv6_hlmt_i, ipv6_src_i, ipv6_dst_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_I_Protocol) {
            Ipv6_I_Protocol that = (Ipv6_I_Protocol) obj;
            return Objects.equals(ipv6_ver_tp_flb_i, that.ipv6_ver_tp_flb_i) && Objects.equals(ipv6_plen_i, that.ipv6_plen_i) && Objects.equals(ipv6_i_type, that.ipv6_i_type) && Objects.equals(ipv6_hlmt_i, that.ipv6_hlmt_i) && Objects.equals(ipv6_src_i, that.ipv6_src_i) && Objects.equals(ipv6_dst_i, that.ipv6_dst_i);
        }
        return false;
    }
    public static Ipv6_I_Protocol readWithMask(ByteBuf bb){
        Ipv6_Ver_Tp_Flb_ICriterion.Builder b1 = new Ipv6_Ver_Tp_Flb_ICriterion.Builder();
        Ipv6_Plen_ICriterion.Builder b2 = new Ipv6_Plen_ICriterion.Builder();
        Ipv6_I_TypeCriterion.Builder b3 = new Ipv6_I_TypeCriterion.Builder();
        Ipv6_Hlmt_ICriterion.Builder b4 = new Ipv6_Hlmt_ICriterion.Builder();
        Ipv6_Src_ICriterion.Builder b5 = new Ipv6_Src_ICriterion.Builder();
        Ipv6_Dst_ICriterion.Builder b6 = new Ipv6_Dst_ICriterion.Builder();
        b1.readMask(bb);
        b2.readMask(bb);
        b3.readMask(bb);
        b4.readMask(bb);
        b5.readMask(bb);
        b6.readMask(bb);
        bb.skipBytes(16);

        b1.readData(bb);
        b2.readData(bb);
        b3.readData(bb);
        b4.readData(bb);
        b5.readData(bb);
        b6.readData(bb);
        bb.skipBytes(16);

        return new Ipv6_I_Protocol(b1.build(), b2.build(), b3.build(), b4.build(), b5.build(), b6.build());
    }
  
}