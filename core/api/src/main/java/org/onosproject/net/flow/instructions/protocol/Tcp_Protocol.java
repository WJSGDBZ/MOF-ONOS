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
    Tcp_SourceCriterion tcp_source;
    Tcp_DestCriterion tcp_dest;
    SeqCriterion seq;
    Ack_SeqCriterion ack_seq;
    Off_BitsCriterion off_bits;
    WindowCriterion window;
    Tcp_CheckCriterion tcp_check;
    Urg_PtrCriterion urg_ptr;

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

}
