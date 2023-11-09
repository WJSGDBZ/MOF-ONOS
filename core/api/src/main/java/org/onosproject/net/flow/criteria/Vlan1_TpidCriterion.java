package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Vlan1_TpidCriterion implements Criterion {


    private final long vlan1_tpid;
  	private final long mask;

    public static final int LEN = 2;

    Vlan1_TpidCriterion(long vlan1_tpid) {
        this(vlan1_tpid, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param vlan1_tpid the Ethernet frame type to match
     */
    Vlan1_TpidCriterion(long vlan1_tpid, long mask) {
        this.vlan1_tpid = vlan1_tpid;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)vlan1_tpid);
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
        return Type.VLAN1_TPID;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long vlan1_tpid() {
        return vlan1_tpid;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(vlan1_tpid, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), vlan1_tpid);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Vlan1_TpidCriterion) {
            Vlan1_TpidCriterion that = (Vlan1_TpidCriterion) obj;
            return vlan1_tpid == that.vlan1_tpid && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long vlan1_tpid;
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
            vlan1_tpid = bb.readShort();
            return this;
        }

        @Override
        public Vlan1_TpidCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Vlan1_TpidCriterion Mask should not be zero");
            }
            return new Vlan1_TpidCriterion(vlan1_tpid, mask);
        }
    }
}
