package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Udp_SourceCriterion;
import org.onosproject.net.flow.criteria.Udp_DestCriterion;
import org.onosproject.net.flow.criteria.LenCriterion;
import org.onosproject.net.flow.criteria.Udp_CheckCriterion;

public class Udp_Protocol implements Protocol {
    public Udp_SourceCriterion udp_source;
    public Udp_DestCriterion udp_dest;
    public LenCriterion len;
    public Udp_CheckCriterion udp_check;
    public static int LEN = Udp_SourceCriterion.LEN + Udp_DestCriterion.LEN + LenCriterion.LEN + Udp_CheckCriterion.LEN;

    public Udp_Protocol(Udp_SourceCriterion udp_source, Udp_DestCriterion udp_dest, LenCriterion len, Udp_CheckCriterion udp_check){
        this.udp_source = udp_source;
        this.udp_dest = udp_dest;
        this.len = len;
        this.udp_check = udp_check;
    }

    @Override
    public void write(ByteBuf bb){
        udp_source.write(bb);
        udp_dest.write(bb);
        len.write(bb);
        udp_check.write(bb);
        bb.writeZero(48);
    }
  
    @Override
    public void writeMask(ByteBuf bb){
        udp_source.writeMask(bb);
        udp_dest.writeMask(bb);
        len.writeMask(bb);
        udp_check.writeMask(bb);
        bb.writeZero(48);
    }
  
    public static Udp_Protocol read(ByteBuf bb){
        Udp_SourceCriterion udp_source = new Udp_SourceCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Udp_DestCriterion udp_dest = new Udp_DestCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        LenCriterion len = new LenCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Udp_CheckCriterion udp_check = new Udp_CheckCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        bb.skipBytes(48);
        return new Udp_Protocol(udp_source, udp_dest, len, udp_check);
    }

    @Override
    public String toString() {
        return "Udp_Protocol{ " + udp_source + ", " + udp_dest + ", " + len + ", " + udp_check + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(udp_source, udp_dest, len, udp_check);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Udp_Protocol) {
            Udp_Protocol that = (Udp_Protocol) obj;
            return Objects.equals(udp_source, that.udp_source) && Objects.equals(udp_dest, that.udp_dest) && Objects.equals(len, that.len) && Objects.equals(udp_check, that.udp_check);
        }
        return false;
    }
    public static Udp_Protocol readWithMask(ByteBuf bb){
        Udp_SourceCriterion.Builder b1 = new Udp_SourceCriterion.Builder();
        Udp_DestCriterion.Builder b2 = new Udp_DestCriterion.Builder();
        LenCriterion.Builder b3 = new LenCriterion.Builder();
        Udp_CheckCriterion.Builder b4 = new Udp_CheckCriterion.Builder();
        b1.readData(bb);
        b2.readData(bb);
        b3.readData(bb);
        b4.readData(bb);
        bb.skipBytes(48);

        b1.readMask(bb);
        b2.readMask(bb);
        b3.readMask(bb);
        b4.readMask(bb);
        bb.skipBytes(48);

        return new Udp_Protocol(b1.build(), b2.build(), b3.build(), b4.build());
    }
  
}