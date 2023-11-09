package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Vlan2_TpidCriterion;
import org.onosproject.net.flow.criteria.Vlan2_QidCriterion;

public class Vlan2_Protocol implements Protocol {
    Vlan2_TpidCriterion vlan2_tpid;
    Vlan2_QidCriterion vlan2_qid;

    public Vlan2_Protocol(Vlan2_TpidCriterion vlan2_tpid, Vlan2_QidCriterion vlan2_qid){
        this.vlan2_tpid = vlan2_tpid;
        this.vlan2_qid = vlan2_qid;
    }

    @Override
    public void write(ByteBuf bb){
        vlan2_tpid.write(bb);
        vlan2_qid.write(bb);

    }
  
    @Override
    public void writeMask(ByteBuf bb){
        vlan2_tpid.writeMask(bb);
        vlan2_qid.writeMask(bb);
    }
  
    public static Vlan2_Protocol read(ByteBuf bb){
        Vlan2_TpidCriterion vlan2_tpid = new Vlan2_TpidCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Vlan2_QidCriterion vlan2_qid = new Vlan2_QidCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        return new Vlan2_Protocol(vlan2_tpid, vlan2_qid);
    }

    @Override
    public String toString() {
        return "Vlan2_Protocol{ " + vlan2_tpid + ", " + vlan2_qid + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(vlan2_tpid, vlan2_qid);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Vlan2_Protocol) {
            Vlan2_Protocol that = (Vlan2_Protocol) obj;
            return Objects.equals(vlan2_tpid, that.vlan2_tpid) && Objects.equals(vlan2_qid, that.vlan2_qid);
        }
        return false;
    }

}
