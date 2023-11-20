package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Mac_DstCriterion;
import org.onosproject.net.flow.criteria.Mac_SrcCriterion;

public class Mac_Protocol implements Protocol {
    Mac_DstCriterion mac_dst;
    Mac_SrcCriterion mac_src;

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

}
