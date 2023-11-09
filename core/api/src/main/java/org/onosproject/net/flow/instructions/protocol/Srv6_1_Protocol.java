package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Srv6_TypeCriterion;
import org.onosproject.net.flow.criteria.Srv6_Hdr_Ext_LenCriterion;
import org.onosproject.net.flow.criteria.Srv6_Routing_TypeCriterion;
import org.onosproject.net.flow.criteria.Srv6_Segments_LeftCriterion;
import org.onosproject.net.flow.criteria.Srv6_Last_EntyCriterion;
import org.onosproject.net.flow.criteria.Srv6_FlagsCriterion;
import org.onosproject.net.flow.criteria.Srv6_TagCriterion;
import org.onosproject.net.flow.criteria.Srv6_Segmentlist1Criterion;

public class Srv6_1_Protocol implements Protocol {
    Srv6_TypeCriterion srv6_type;
    Srv6_Hdr_Ext_LenCriterion srv6_hdr_ext_len;
    Srv6_Routing_TypeCriterion srv6_routing_Type;
    Srv6_Segments_LeftCriterion srv6_segments_left;
    Srv6_Last_EntyCriterion srv6_last_enty;
    Srv6_FlagsCriterion srv6_flags;
    Srv6_TagCriterion srv6_tag;
    Srv6_Segmentlist1Criterion srv6_segmentlist1;

    public Srv6_1_Protocol(Srv6_TypeCriterion srv6_type, Srv6_Hdr_Ext_LenCriterion srv6_hdr_ext_len, Srv6_Routing_TypeCriterion srv6_routing_Type, Srv6_Segments_LeftCriterion srv6_segments_left, Srv6_Last_EntyCriterion srv6_last_enty, Srv6_FlagsCriterion srv6_flags, Srv6_TagCriterion srv6_tag, Srv6_Segmentlist1Criterion srv6_segmentlist1){
        this.srv6_type = srv6_type;
        this.srv6_hdr_ext_len = srv6_hdr_ext_len;
        this.srv6_routing_Type = srv6_routing_Type;
        this.srv6_segments_left = srv6_segments_left;
        this.srv6_last_enty = srv6_last_enty;
        this.srv6_flags = srv6_flags;
        this.srv6_tag = srv6_tag;
        this.srv6_segmentlist1 = srv6_segmentlist1;
    }

    @Override
    public void write(ByteBuf bb){
        srv6_type.write(bb);
        srv6_hdr_ext_len.write(bb);
        srv6_routing_Type.write(bb);
        srv6_segments_left.write(bb);
        srv6_last_enty.write(bb);
        srv6_flags.write(bb);
        srv6_tag.write(bb);
        srv6_segmentlist1.write(bb);

    }
  
    @Override
    public void writeMask(ByteBuf bb){
        srv6_type.writeMask(bb);
        srv6_hdr_ext_len.writeMask(bb);
        srv6_routing_Type.writeMask(bb);
        srv6_segments_left.writeMask(bb);
        srv6_last_enty.writeMask(bb);
        srv6_flags.writeMask(bb);
        srv6_tag.writeMask(bb);
        srv6_segmentlist1.writeMask(bb);
    }
  
    public static Srv6_1_Protocol read(ByteBuf bb){
        Srv6_TypeCriterion srv6_type = new Srv6_TypeCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Srv6_Hdr_Ext_LenCriterion srv6_hdr_ext_len = new Srv6_Hdr_Ext_LenCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Srv6_Routing_TypeCriterion srv6_routing_Type = new Srv6_Routing_TypeCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Srv6_Segments_LeftCriterion srv6_segments_left = new Srv6_Segments_LeftCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Srv6_Last_EntyCriterion srv6_last_enty = new Srv6_Last_EntyCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Srv6_FlagsCriterion srv6_flags = new Srv6_FlagsCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Srv6_TagCriterion srv6_tag = new Srv6_TagCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Srv6_Segmentlist1Criterion srv6_segmentlist1 = new Srv6_Segmentlist1Criterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        return new Srv6_1_Protocol(srv6_type, srv6_hdr_ext_len, srv6_routing_Type, srv6_segments_left, srv6_last_enty, srv6_flags, srv6_tag, srv6_segmentlist1);
    }

    @Override
    public String toString() {
        return "Srv6_1_Protocol{ " + srv6_type + ", " + srv6_hdr_ext_len + ", " + srv6_routing_Type + ", " + srv6_segments_left + ", " + srv6_last_enty + ", " + srv6_flags + ", " + srv6_tag + ", " + srv6_segmentlist1 + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(srv6_type, srv6_hdr_ext_len, srv6_routing_Type, srv6_segments_left, srv6_last_enty, srv6_flags, srv6_tag, srv6_segmentlist1);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Srv6_1_Protocol) {
            Srv6_1_Protocol that = (Srv6_1_Protocol) obj;
            return Objects.equals(srv6_type, that.srv6_type) && Objects.equals(srv6_hdr_ext_len, that.srv6_hdr_ext_len) && Objects.equals(srv6_routing_Type, that.srv6_routing_Type) && Objects.equals(srv6_segments_left, that.srv6_segments_left) && Objects.equals(srv6_last_enty, that.srv6_last_enty) && Objects.equals(srv6_flags, that.srv6_flags) && Objects.equals(srv6_tag, that.srv6_tag) && Objects.equals(srv6_segmentlist1, that.srv6_segmentlist1);
        }
        return false;
    }

}
