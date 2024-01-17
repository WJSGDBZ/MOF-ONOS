package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Tcp_SourceCriterion;
import org.onosproject.net.flow.criteria.Tcp_DestCriterion;
import org.onosproject.net.flow.criteria.SeqCriterion;
import org.onosproject.net.flow.criteria.Ack_SeqCriterion;
import org.onosproject.net.flow.criteria.Off_BitsCriterion;
import org.onosproject.net.flow.criteria.WindowCriterion;
import org.onosproject.net.flow.criteria.Tcp_CheckCriterion;
import org.onosproject.net.flow.criteria.Urg_PtrCriterion;

public class Tcp_Protocol implements Protocol {
    public Tcp_SourceCriterion tcp_source;
    public Tcp_DestCriterion tcp_dest;
    public SeqCriterion seq;
    public Ack_SeqCriterion ack_seq;
    public Off_BitsCriterion off_bits;
    public WindowCriterion window;
    public Tcp_CheckCriterion tcp_check;
    public Urg_PtrCriterion urg_ptr;
    public static int LEN = Tcp_SourceCriterion.LEN + Tcp_DestCriterion.LEN + SeqCriterion.LEN + Ack_SeqCriterion.LEN + Off_BitsCriterion.LEN + WindowCriterion.LEN + Tcp_CheckCriterion.LEN + Urg_PtrCriterion.LEN;

    public Tcp_Protocol(Tcp_SourceCriterion tcp_source, Tcp_DestCriterion tcp_dest, SeqCriterion seq, Ack_SeqCriterion ack_seq, Off_BitsCriterion off_bits, WindowCriterion window, Tcp_CheckCriterion tcp_check, Urg_PtrCriterion urg_ptr){
        this.tcp_source = tcp_source;
        this.tcp_dest = tcp_dest;
        this.seq = seq;
        this.ack_seq = ack_seq;
        this.off_bits = off_bits;
        this.window = window;
        this.tcp_check = tcp_check;
        this.urg_ptr = urg_ptr;
    }

    @Override
    public void write(ByteBuf bb){
        tcp_source.write(bb);
        tcp_dest.write(bb);
        seq.write(bb);
        ack_seq.write(bb);
        off_bits.write(bb);
        window.write(bb);
        tcp_check.write(bb);
        urg_ptr.write(bb);
        bb.writeZero(36);
    }
  
    @Override
    public void writeMask(ByteBuf bb){
        tcp_source.writeMask(bb);
        tcp_dest.writeMask(bb);
        seq.writeMask(bb);
        ack_seq.writeMask(bb);
        off_bits.writeMask(bb);
        window.writeMask(bb);
        tcp_check.writeMask(bb);
        urg_ptr.writeMask(bb);
        bb.writeZero(36);
    }
  
    public static Tcp_Protocol read(ByteBuf bb){
        Tcp_SourceCriterion tcp_source = new Tcp_SourceCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Tcp_DestCriterion tcp_dest = new Tcp_DestCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        SeqCriterion seq = new SeqCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Ack_SeqCriterion ack_seq = new Ack_SeqCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Off_BitsCriterion off_bits = new Off_BitsCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        WindowCriterion window = new WindowCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Tcp_CheckCriterion tcp_check = new Tcp_CheckCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Urg_PtrCriterion urg_ptr = new Urg_PtrCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        bb.skipBytes(36);
        return new Tcp_Protocol(tcp_source, tcp_dest, seq, ack_seq, off_bits, window, tcp_check, urg_ptr);
    }

    @Override
    public String toString() {
        return "Tcp_Protocol{ " + tcp_source + ", " + tcp_dest + ", " + seq + ", " + ack_seq + ", " + off_bits + ", " + window + ", " + tcp_check + ", " + urg_ptr + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(tcp_source, tcp_dest, seq, ack_seq, off_bits, window, tcp_check, urg_ptr);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Tcp_Protocol) {
            Tcp_Protocol that = (Tcp_Protocol) obj;
            return Objects.equals(tcp_source, that.tcp_source) && Objects.equals(tcp_dest, that.tcp_dest) && Objects.equals(seq, that.seq) && Objects.equals(ack_seq, that.ack_seq) && Objects.equals(off_bits, that.off_bits) && Objects.equals(window, that.window) && Objects.equals(tcp_check, that.tcp_check) && Objects.equals(urg_ptr, that.urg_ptr);
        }
        return false;
    }
    public static Tcp_Protocol readWithMask(ByteBuf bb){
        Tcp_SourceCriterion.Builder b1 = new Tcp_SourceCriterion.Builder();
        Tcp_DestCriterion.Builder b2 = new Tcp_DestCriterion.Builder();
        SeqCriterion.Builder b3 = new SeqCriterion.Builder();
        Ack_SeqCriterion.Builder b4 = new Ack_SeqCriterion.Builder();
        Off_BitsCriterion.Builder b5 = new Off_BitsCriterion.Builder();
        WindowCriterion.Builder b6 = new WindowCriterion.Builder();
        Tcp_CheckCriterion.Builder b7 = new Tcp_CheckCriterion.Builder();
        Urg_PtrCriterion.Builder b8 = new Urg_PtrCriterion.Builder();
        b1.readData(bb);
        b2.readData(bb);
        b3.readData(bb);
        b4.readData(bb);
        b5.readData(bb);
        b6.readData(bb);
        b7.readData(bb);
        b8.readData(bb);
        bb.skipBytes(36);

        b1.readMask(bb);
        b2.readMask(bb);
        b3.readMask(bb);
        b4.readMask(bb);
        b5.readMask(bb);
        b6.readMask(bb);
        b7.readMask(bb);
        b8.readMask(bb);
        bb.skipBytes(36);

        return new Tcp_Protocol(b1.build(), b2.build(), b3.build(), b4.build(), b5.build(), b6.build(), b7.build(), b8.build());
    }
  
}