package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Vlan1_QidCriterion implements Criterion {


    private final long vlan1_qid;
  	private final long mask;

    public static final int LEN = 2;

    Vlan1_QidCriterion(long vlan1_qid) {
        this(vlan1_qid, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param vlan1_qid the Ethernet frame type to match
     */
    Vlan1_QidCriterion(long vlan1_qid, long mask) {
        this.vlan1_qid = vlan1_qid;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)vlan1_qid);
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
        return Type.VLAN1_QID;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long vlan1_qid() {
        return vlan1_qid;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(vlan1_qid, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), vlan1_qid);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Vlan1_QidCriterion) {
            Vlan1_QidCriterion that = (Vlan1_QidCriterion) obj;
            return vlan1_qid == that.vlan1_qid && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long vlan1_qid;
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
            vlan1_qid = bb.readShort();
            return this;
        }

        @Override
        public Vlan1_QidCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Vlan1_QidCriterion Mask should not be zero");
            }
            return new Vlan1_QidCriterion(vlan1_qid, mask);
        }
    }
}
