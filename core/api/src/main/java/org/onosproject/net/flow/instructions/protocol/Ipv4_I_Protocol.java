package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Ver_Hl_ICriterion;
import org.onosproject.net.flow.criteria.Tos_ICriterion;
import org.onosproject.net.flow.criteria.Tot_Len_ICriterion;
import org.onosproject.net.flow.criteria.Ip_Id_ICriterion;
import org.onosproject.net.flow.criteria.Frag_Off_ICriterion;
import org.onosproject.net.flow.criteria.Ttl_ICriterion;
import org.onosproject.net.flow.criteria.Ipv4_I_TypeCriterion;
import org.onosproject.net.flow.criteria.Ip_Check_ICriterion;
import org.onosproject.net.flow.criteria.Ip_Saddr_ICriterion;
import org.onosproject.net.flow.criteria.Ip_Daddr_ICriterion;

public class Ipv4_I_Protocol implements Protocol {
    public Ver_Hl_ICriterion ver_hl_i;
    public Tos_ICriterion tos_i;
    public Tot_Len_ICriterion tot_len_i;
    public Ip_Id_ICriterion ip_id_i;
    public Frag_Off_ICriterion frag_off_i;
    public Ttl_ICriterion ttl_i;
    public Ipv4_I_TypeCriterion ipv4_i_type;
    public Ip_Check_ICriterion ip_check_i;
    public Ip_Saddr_ICriterion ip_saddr_i;
    public Ip_Daddr_ICriterion ip_daddr_i;
    public static int LEN = Ver_Hl_ICriterion.LEN + Tos_ICriterion.LEN + Tot_Len_ICriterion.LEN + Ip_Id_ICriterion.LEN + Frag_Off_ICriterion.LEN + Ttl_ICriterion.LEN + Ipv4_I_TypeCriterion.LEN + Ip_Check_ICriterion.LEN + Ip_Saddr_ICriterion.LEN + Ip_Daddr_ICriterion.LEN;

    public Ipv4_I_Protocol(Ver_Hl_ICriterion ver_hl_i, Tos_ICriterion tos_i, Tot_Len_ICriterion tot_len_i, Ip_Id_ICriterion ip_id_i, Frag_Off_ICriterion frag_off_i, Ttl_ICriterion ttl_i, Ipv4_I_TypeCriterion ipv4_i_type, Ip_Check_ICriterion ip_check_i, Ip_Saddr_ICriterion ip_saddr_i, Ip_Daddr_ICriterion ip_daddr_i){
        this.ver_hl_i = ver_hl_i;
        this.tos_i = tos_i;
        this.tot_len_i = tot_len_i;
        this.ip_id_i = ip_id_i;
        this.frag_off_i = frag_off_i;
        this.ttl_i = ttl_i;
        this.ipv4_i_type = ipv4_i_type;
        this.ip_check_i = ip_check_i;
        this.ip_saddr_i = ip_saddr_i;
        this.ip_daddr_i = ip_daddr_i;
    }

    @Override
    public void write(ByteBuf bb){
        ver_hl_i.write(bb);
        tos_i.write(bb);
        tot_len_i.write(bb);
        ip_id_i.write(bb);
        frag_off_i.write(bb);
        ttl_i.write(bb);
        ipv4_i_type.write(bb);
        ip_check_i.write(bb);
        ip_saddr_i.write(bb);
        ip_daddr_i.write(bb);
        bb.writeZero(36);
    }
  
    @Override
    public void writeMask(ByteBuf bb){
        ver_hl_i.writeMask(bb);
        tos_i.writeMask(bb);
        tot_len_i.writeMask(bb);
        ip_id_i.writeMask(bb);
        frag_off_i.writeMask(bb);
        ttl_i.writeMask(bb);
        ipv4_i_type.writeMask(bb);
        ip_check_i.writeMask(bb);
        ip_saddr_i.writeMask(bb);
        ip_daddr_i.writeMask(bb);
        bb.writeZero(36);
    }
  
    public static Ipv4_I_Protocol read(ByteBuf bb){
        Ver_Hl_ICriterion ver_hl_i = new Ver_Hl_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Tos_ICriterion tos_i = new Tos_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Tot_Len_ICriterion tot_len_i = new Tot_Len_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ip_Id_ICriterion ip_id_i = new Ip_Id_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Frag_Off_ICriterion frag_off_i = new Frag_Off_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ttl_ICriterion ttl_i = new Ttl_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ipv4_I_TypeCriterion ipv4_i_type = new Ipv4_I_TypeCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ip_Check_ICriterion ip_check_i = new Ip_Check_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ip_Saddr_ICriterion ip_saddr_i = new Ip_Saddr_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ip_Daddr_ICriterion ip_daddr_i = new Ip_Daddr_ICriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        bb.skipBytes(36);
        return new Ipv4_I_Protocol(ver_hl_i, tos_i, tot_len_i, ip_id_i, frag_off_i, ttl_i, ipv4_i_type, ip_check_i, ip_saddr_i, ip_daddr_i);
    }

    @Override
    public String toString() {
        return "Ipv4_I_Protocol{ " + ver_hl_i + ", " + tos_i + ", " + tot_len_i + ", " + ip_id_i + ", " + frag_off_i + ", " + ttl_i + ", " + ipv4_i_type + ", " + ip_check_i + ", " + ip_saddr_i + ", " + ip_daddr_i + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(ver_hl_i, tos_i, tot_len_i, ip_id_i, frag_off_i, ttl_i, ipv4_i_type, ip_check_i, ip_saddr_i, ip_daddr_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv4_I_Protocol) {
            Ipv4_I_Protocol that = (Ipv4_I_Protocol) obj;
            return Objects.equals(ver_hl_i, that.ver_hl_i) && Objects.equals(tos_i, that.tos_i) && Objects.equals(tot_len_i, that.tot_len_i) && Objects.equals(ip_id_i, that.ip_id_i) && Objects.equals(frag_off_i, that.frag_off_i) && Objects.equals(ttl_i, that.ttl_i) && Objects.equals(ipv4_i_type, that.ipv4_i_type) && Objects.equals(ip_check_i, that.ip_check_i) && Objects.equals(ip_saddr_i, that.ip_saddr_i) && Objects.equals(ip_daddr_i, that.ip_daddr_i);
        }
        return false;
    }
    public static Ipv4_I_Protocol readWithMask(ByteBuf bb){
        Ver_Hl_ICriterion.Builder b1 = new Ver_Hl_ICriterion.Builder();
        Tos_ICriterion.Builder b2 = new Tos_ICriterion.Builder();
        Tot_Len_ICriterion.Builder b3 = new Tot_Len_ICriterion.Builder();
        Ip_Id_ICriterion.Builder b4 = new Ip_Id_ICriterion.Builder();
        Frag_Off_ICriterion.Builder b5 = new Frag_Off_ICriterion.Builder();
        Ttl_ICriterion.Builder b6 = new Ttl_ICriterion.Builder();
        Ipv4_I_TypeCriterion.Builder b7 = new Ipv4_I_TypeCriterion.Builder();
        Ip_Check_ICriterion.Builder b8 = new Ip_Check_ICriterion.Builder();
        Ip_Saddr_ICriterion.Builder b9 = new Ip_Saddr_ICriterion.Builder();
        Ip_Daddr_ICriterion.Builder b10 = new Ip_Daddr_ICriterion.Builder();
        b1.readData(bb);
        b2.readData(bb);
        b3.readData(bb);
        b4.readData(bb);
        b5.readData(bb);
        b6.readData(bb);
        b7.readData(bb);
        b8.readData(bb);
        b9.readData(bb);
        b10.readData(bb);
        bb.skipBytes(36);

        b1.readMask(bb);
        b2.readMask(bb);
        b3.readMask(bb);
        b4.readMask(bb);
        b5.readMask(bb);
        b6.readMask(bb);
        b7.readMask(bb);
        b8.readMask(bb);
        b9.readMask(bb);
        b10.readMask(bb);
        bb.skipBytes(36);

        return new Ipv4_I_Protocol(b1.build(), b2.build(), b3.build(), b4.build(), b5.build(), b6.build(), b7.build(), b8.build(), b9.build(), b10.build());
    }
  
}