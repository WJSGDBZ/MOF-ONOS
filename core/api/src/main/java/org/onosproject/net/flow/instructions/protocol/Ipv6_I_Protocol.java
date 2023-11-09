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
    Ipv6_Ver_Tp_Flb_ICriterion ipv6_ver_tp_flb_i;
    Ipv6_Plen_ICriterion ipv6_plen_i;
    Ipv6_I_TypeCriterion ipv6_i_type;
    Ipv6_Hlmt_ICriterion ipv6_hlmt_i;
    Ipv6_Src_ICriterion ipv6_src_i;
    Ipv6_Dst_ICriterion ipv6_dst_i;

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

    }
  
    @Override
    public void writeMask(ByteBuf bb){
        ipv6_ver_tp_flb_i.writeMask(bb);
        ipv6_plen_i.writeMask(bb);
        ipv6_i_type.writeMask(bb);
        ipv6_hlmt_i.writeMask(bb);
        ipv6_src_i.writeMask(bb);
        ipv6_dst_i.writeMask(bb);
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

}
