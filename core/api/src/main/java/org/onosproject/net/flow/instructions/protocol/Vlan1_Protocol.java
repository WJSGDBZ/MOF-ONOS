package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Vlan1_TpidCriterion;
import org.onosproject.net.flow.criteria.Vlan1_QidCriterion;

public class Vlan1_Protocol implements Protocol {
    public Vlan1_TpidCriterion vlan1_tpid;
    public Vlan1_QidCriterion vlan1_qid;
    public static int LEN = Vlan1_TpidCriterion.LEN + Vlan1_QidCriterion.LEN;

    public Vlan1_Protocol(Vlan1_TpidCriterion vlan1_tpid, Vlan1_QidCriterion vlan1_qid){
        this.vlan1_tpid = vlan1_tpid;
        this.vlan1_qid = vlan1_qid;
    }

    @Override
    public void write(ByteBuf bb){
        vlan1_tpid.write(bb);
        vlan1_qid.write(bb);
        bb.writeZero(52);
    }
  
    @Override
    public void writeMask(ByteBuf bb){
        vlan1_tpid.writeMask(bb);
        vlan1_qid.writeMask(bb);
        bb.writeZero(52);
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

        bb.skipBytes(52);
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
    public static Vlan1_Protocol readWithMask(ByteBuf bb){
        Vlan1_TpidCriterion.Builder b1 = new Vlan1_TpidCriterion.Builder();
        Vlan1_QidCriterion.Builder b2 = new Vlan1_QidCriterion.Builder();
        b1.readData(bb);
        b2.readData(bb);
        bb.skipBytes(52);

        b1.readMask(bb);
        b2.readMask(bb);
        bb.skipBytes(52);

        return new Vlan1_Protocol(b1.build(), b2.build());
    }
  
}