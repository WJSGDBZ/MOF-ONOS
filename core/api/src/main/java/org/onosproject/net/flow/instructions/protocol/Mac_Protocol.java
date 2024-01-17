package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Mac_DstCriterion;
import org.onosproject.net.flow.criteria.Mac_SrcCriterion;

public class Mac_Protocol implements Protocol {
    public Mac_DstCriterion mac_dst;
    public Mac_SrcCriterion mac_src;
    public static int LEN = Mac_DstCriterion.LEN + Mac_SrcCriterion.LEN;

    public Mac_Protocol(Mac_DstCriterion mac_dst, Mac_SrcCriterion mac_src){
        this.mac_dst = mac_dst;
        this.mac_src = mac_src;
    }

    @Override
    public void write(ByteBuf bb){
        mac_dst.write(bb);
        mac_src.write(bb);
        bb.writeZero(44);
    }
  
    @Override
    public void writeMask(ByteBuf bb){
        mac_dst.writeMask(bb);
        mac_src.writeMask(bb);
        bb.writeZero(44);
    }
  
    public static Mac_Protocol read(ByteBuf bb){
        Mac_DstCriterion mac_dst = new Mac_DstCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Mac_SrcCriterion mac_src = new Mac_SrcCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        bb.skipBytes(44);
        return new Mac_Protocol(mac_dst, mac_src);
    }

    @Override
    public String toString() {
        return "Mac_Protocol{ " + mac_dst + ", " + mac_src + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(mac_dst, mac_src);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Mac_Protocol) {
            Mac_Protocol that = (Mac_Protocol) obj;
            return Objects.equals(mac_dst, that.mac_dst) && Objects.equals(mac_src, that.mac_src);
        }
        return false;
    }
    public static Mac_Protocol readWithMask(ByteBuf bb){
        Mac_DstCriterion.Builder b1 = new Mac_DstCriterion.Builder();
        Mac_SrcCriterion.Builder b2 = new Mac_SrcCriterion.Builder();
        b1.readData(bb);
        b2.readData(bb);
        bb.skipBytes(44);

        b1.readMask(bb);
        b2.readMask(bb);
        bb.skipBytes(44);

        return new Mac_Protocol(b1.build(), b2.build());
    }
  
}