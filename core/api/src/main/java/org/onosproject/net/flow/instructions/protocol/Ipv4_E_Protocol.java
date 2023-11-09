package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Ver_Hl_ECriterion;
import org.onosproject.net.flow.criteria.Tos_ECriterion;
import org.onosproject.net.flow.criteria.Tot_Len_ECriterion;
import org.onosproject.net.flow.criteria.Ip_Id_ECriterion;
import org.onosproject.net.flow.criteria.Frag_Off_ECriterion;
import org.onosproject.net.flow.criteria.Ttl_ECriterion;
import org.onosproject.net.flow.criteria.Ipv4_E_TypeCriterion;
import org.onosproject.net.flow.criteria.Ip_Check_ECriterion;
import org.onosproject.net.flow.criteria.Ip_Saddr_ECriterion;
import org.onosproject.net.flow.criteria.Ip_Daddr_ECriterion;

public class Ipv4_E_Protocol implements Protocol {
    Ver_Hl_ECriterion ver_hl_e;
    Tos_ECriterion tos_e;
    Tot_Len_ECriterion tot_len_e;
    Ip_Id_ECriterion ip_id_e;
    Frag_Off_ECriterion frag_off_e;
    Ttl_ECriterion ttl_e;
    Ipv4_E_TypeCriterion ipv4_e_type;
    Ip_Check_ECriterion ip_check_e;
    Ip_Saddr_ECriterion ip_saddr_e;
    Ip_Daddr_ECriterion ip_daddr_e;

    public Ipv4_E_Protocol(Ver_Hl_ECriterion ver_hl_e, Tos_ECriterion tos_e, Tot_Len_ECriterion tot_len_e, Ip_Id_ECriterion ip_id_e, Frag_Off_ECriterion frag_off_e, Ttl_ECriterion ttl_e, Ipv4_E_TypeCriterion ipv4_e_type, Ip_Check_ECriterion ip_check_e, Ip_Saddr_ECriterion ip_saddr_e, Ip_Daddr_ECriterion ip_daddr_e){
        this.ver_hl_e = ver_hl_e;
        this.tos_e = tos_e;
        this.tot_len_e = tot_len_e;
        this.ip_id_e = ip_id_e;
        this.frag_off_e = frag_off_e;
        this.ttl_e = ttl_e;
        this.ipv4_e_type = ipv4_e_type;
        this.ip_check_e = ip_check_e;
        this.ip_saddr_e = ip_saddr_e;
        this.ip_daddr_e = ip_daddr_e;
    }

    @Override
    public void write(ByteBuf bb){
        ver_hl_e.write(bb);
        tos_e.write(bb);
        tot_len_e.write(bb);
        ip_id_e.write(bb);
        frag_off_e.write(bb);
        ttl_e.write(bb);
        ipv4_e_type.write(bb);
        ip_check_e.write(bb);
        ip_saddr_e.write(bb);
        ip_daddr_e.write(bb);

    }
  
    @Override
    public void writeMask(ByteBuf bb){
        ver_hl_e.writeMask(bb);
        tos_e.writeMask(bb);
        tot_len_e.writeMask(bb);
        ip_id_e.writeMask(bb);
        frag_off_e.writeMask(bb);
        ttl_e.writeMask(bb);
        ipv4_e_type.writeMask(bb);
        ip_check_e.writeMask(bb);
        ip_saddr_e.writeMask(bb);
        ip_daddr_e.writeMask(bb);
    }
  
    public static Ipv4_E_Protocol read(ByteBuf bb){
        Ver_Hl_ECriterion ver_hl_e = new Ver_Hl_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Tos_ECriterion tos_e = new Tos_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Tot_Len_ECriterion tot_len_e = new Tot_Len_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ip_Id_ECriterion ip_id_e = new Ip_Id_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Frag_Off_ECriterion frag_off_e = new Frag_Off_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ttl_ECriterion ttl_e = new Ttl_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv4_E_TypeCriterion ipv4_e_type = new Ipv4_E_TypeCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ip_Check_ECriterion ip_check_e = new Ip_Check_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ip_Saddr_ECriterion ip_saddr_e = new Ip_Saddr_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ip_Daddr_ECriterion ip_daddr_e = new Ip_Daddr_ECriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        return new Ipv4_E_Protocol(ver_hl_e, tos_e, tot_len_e, ip_id_e, frag_off_e, ttl_e, ipv4_e_type, ip_check_e, ip_saddr_e, ip_daddr_e);
    }

    @Override
    public String toString() {
        return "Ipv4_E_Protocol{ " + ver_hl_e + ", " + tos_e + ", " + tot_len_e + ", " + ip_id_e + ", " + frag_off_e + ", " + ttl_e + ", " + ipv4_e_type + ", " + ip_check_e + ", " + ip_saddr_e + ", " + ip_daddr_e + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(ver_hl_e, tos_e, tot_len_e, ip_id_e, frag_off_e, ttl_e, ipv4_e_type, ip_check_e, ip_saddr_e, ip_daddr_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv4_E_Protocol) {
            Ipv4_E_Protocol that = (Ipv4_E_Protocol) obj;
            return Objects.equals(ver_hl_e, that.ver_hl_e) && Objects.equals(tos_e, that.tos_e) && Objects.equals(tot_len_e, that.tot_len_e) && Objects.equals(ip_id_e, that.ip_id_e) && Objects.equals(frag_off_e, that.frag_off_e) && Objects.equals(ttl_e, that.ttl_e) && Objects.equals(ipv4_e_type, that.ipv4_e_type) && Objects.equals(ip_check_e, that.ip_check_e) && Objects.equals(ip_saddr_e, that.ip_saddr_e) && Objects.equals(ip_daddr_e, that.ip_daddr_e);
        }
        return false;
    }

}
