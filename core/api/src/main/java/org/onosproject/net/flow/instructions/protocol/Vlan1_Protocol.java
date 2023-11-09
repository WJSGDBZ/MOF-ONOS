package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Vlan1_TpidCriterion;
import org.onosproject.net.flow.criteria.Vlan1_QidCriterion;

public class Vlan1_Protocol implements Protocol {
    Vlan1_TpidCriterion vlan1_tpid;
    Vlan1_QidCriterion vlan1_qid;

    public Vlan1_Protocol(Vlan1_TpidCriterion vlan1_tpid, Vlan1_QidCriterion vlan1_qid){
        this.vlan1_tpid = vlan1_tpid;
        this.vlan1_qid = vlan1_qid;
    }

    @Override
    public void write(ByteBuf bb){
        vlan1_tpid.write(bb);
        vlan1_qid.write(bb);

    }
  
    @Override
    public void writeMask(ByteBuf bb){
        vlan1_tpid.writeMask(bb);
        vlan1_qid.writeMask(bb);
    }
  
    public static Vlan1_Protocol read(ByteBuf bb){
        Vlan1_TpidCriterion vlan1_tpid = new Vlan1_TpidCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        Vlan1_QidCriterion vlan1_qid = new Vlan1_QidCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();

        return new Vlan1_Protocol(vlan1_tpid, vlan1_qid);
    }

    @Override
    public String toString() {
        return "Vlan1_Protocol{ " + vlan1_tpid + ", " + vlan1_qid + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(vlan1_tpid, vlan1_qid);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Vlan1_Protocol) {
            Vlan1_Protocol that = (Vlan1_Protocol) obj;
            return Objects.equals(vlan1_tpid, that.vlan1_tpid) && Objects.equals(vlan1_qid, that.vlan1_qid);
        }
        return false;
    }

}
