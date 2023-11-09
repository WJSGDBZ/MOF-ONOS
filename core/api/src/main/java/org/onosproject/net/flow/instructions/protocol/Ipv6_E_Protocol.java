package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Ipv6_Ver_Tp_Flb_ECriterion;
import org.onosproject.net.flow.criteria.Ipv6_Plen_ECriterion;
import org.onosproject.net.flow.criteria.Ipv6_E_TypeCriterion;
import org.onosproject.net.flow.criteria.Ipv6_Hlmt_ECriterion;
import org.onosproject.net.flow.criteria.Ipv6_Src_ECriterion;
import org.onosproject.net.flow.criteria.Ipv6_Dst_ECriterion;

public class Ipv6_E_Protocol implements Protocol {
    Ipv6_Ver_Tp_Flb_ECriterion ipv6_ver_tp_flb_e;
    Ipv6_Plen_ECriterion ipv6_plen_e;
    Ipv6_E_TypeCriterion ipv6_e_type;
    Ipv6_Hlmt_ECriterion ipv6_hlmt_e;
    Ipv6_Src_ECriterion ipv6_src_e;
    Ipv6_Dst_ECriterion ipv6_dst_e;

    public Ipv6_E_Protocol(Ipv6_Ver_Tp_Flb_ECriterion ipv6_ver_tp_flb_e, Ipv6_Plen_ECriterion ipv6_plen_e, Ipv6_E_TypeCriterion ipv6_e_type, Ipv6_Hlmt_ECriterion ipv6_hlmt_e, Ipv6_Src_ECriterion ipv6_src_e, Ipv6_Dst_ECriterion ipv6_dst_e){
        this.ipv6_ver_tp_flb_e = ipv6_ver_tp_flb_e;
        this.ipv6_plen_e = ipv6_plen_e;
        this.ipv6_e_type = ipv6_e_type;
        this.ipv6_hlmt_e = ipv6_hlmt_e;
        this.ipv6_src_e = ipv6_src_e;
        this.ipv6_dst_e = ipv6_dst_e;
    }

    @Override
    public void write(ByteBuf bb){
        ipv6_ver_tp_flb_e.write(bb);
        ipv6_plen_e.write(bb);
        ipv6_e_type.write(bb);
        ipv6_hlmt_e.write(bb);
        ipv6_src_e.write(bb);
        ipv6_dst_e.write(bb);

    }
  
    @Override
    public void writeMask(ByteBuf bb){
        ipv6_ver_tp_flb_e.writeMask(bb);
        ipv6_plen_e.writeMask(bb);
        ipv6_e_type.writeMask(bb);
        ipv6_hlmt_e.writeMask(bb);
        ipv6_src_e.writeMask(bb);
        ipv6_dst_e.writeMask(bb);
    }
  
    public static Ipv6_E_Protocol read(ByteBuf bb){
        Ipv6_Ver_Tp_Flb_ECriterion ipv6_ver_tp_flb_e = new Ipv6_Ver_Tp_Flb_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_Plen_ECriterion ipv6_plen_e = new Ipv6_Plen_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_E_TypeCriterion ipv6_e_type = new Ipv6_E_TypeCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_Hlmt_ECriterion ipv6_hlmt_e = new Ipv6_Hlmt_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_Src_ECriterion ipv6_src_e = new Ipv6_Src_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv6_Dst_ECriterion ipv6_dst_e = new Ipv6_Dst_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        return new Ipv6_E_Protocol(ipv6_ver_tp_flb_e, ipv6_plen_e, ipv6_e_type, ipv6_hlmt_e, ipv6_src_e, ipv6_dst_e);
    }

    @Override
    public String toString() {
        return "Ipv6_E_Protocol{ " + ipv6_ver_tp_flb_e + ", " + ipv6_plen_e + ", " + ipv6_e_type + ", " + ipv6_hlmt_e + ", " + ipv6_src_e + ", " + ipv6_dst_e + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(ipv6_ver_tp_flb_e, ipv6_plen_e, ipv6_e_type, ipv6_hlmt_e, ipv6_src_e, ipv6_dst_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_E_Protocol) {
            Ipv6_E_Protocol that = (Ipv6_E_Protocol) obj;
            return Objects.equals(ipv6_ver_tp_flb_e, that.ipv6_ver_tp_flb_e) && Objects.equals(ipv6_plen_e, that.ipv6_plen_e) && Objects.equals(ipv6_e_type, that.ipv6_e_type) && Objects.equals(ipv6_hlmt_e, that.ipv6_hlmt_e) && Objects.equals(ipv6_src_e, that.ipv6_src_e) && Objects.equals(ipv6_dst_e, that.ipv6_dst_e);
        }
        return false;
    }

}
