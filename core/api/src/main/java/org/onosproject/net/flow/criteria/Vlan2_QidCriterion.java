package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Vlan2_QidCriterion implements Criterion {


    private final long vlan2_qid;
  	private final long mask;

    public static final int LEN = 2;

    Vlan2_QidCriterion(long vlan2_qid) {
        this(vlan2_qid, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param vlan2_qid the Ethernet frame type to match
     */
    Vlan2_QidCriterion(long vlan2_qid, long mask) {
        this.vlan2_qid = vlan2_qid;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)vlan2_qid);
    }

    @Override
    public void writeMask(ByteBuf bb){
        bb.writeShort((short)mask);
    }

    public static void writeZero(ByteBuf bb){
        bb.writeZero(2);
    }

    @Override
    public Type type() {
        return Type.VLAN2_QID;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long vlan2_qid() {
        return vlan2_qid;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(vlan2_qid, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), vlan2_qid);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Vlan2_QidCriterion) {
            Vlan2_QidCriterion that = (Vlan2_QidCriterion) obj;
            return vlan2_qid == that.vlan2_qid && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long vlan2_qid;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readShort();
            if(mask != 0){
                valid_mask = true;
            }

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            vlan2_qid = bb.readShort();
            return this;
        }

        @Override
        public Vlan2_QidCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Vlan2_QidCriterion Mask should not be zero");
            }
            return new Vlan2_QidCriterion(vlan2_qid, mask);
        }
    }
}
