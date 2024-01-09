package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Vlan2_TpidCriterion implements Criterion {


    private final long vlan2_tpid;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return vlan2_tpid;
    }
  
    public long mask(){
        return mask;
    }

    Vlan2_TpidCriterion(long vlan2_tpid) {
        this(vlan2_tpid, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param vlan2_tpid the Ethernet frame type to match
     */
    Vlan2_TpidCriterion(long vlan2_tpid, long mask) {
        this.vlan2_tpid = vlan2_tpid;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)vlan2_tpid);
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
        return Type.VLAN2_TPID;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long vlan2_tpid() {
        return vlan2_tpid;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(vlan2_tpid, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), vlan2_tpid);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Vlan2_TpidCriterion) {
            Vlan2_TpidCriterion that = (Vlan2_TpidCriterion) obj;
            return vlan2_tpid == that.vlan2_tpid && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long vlan2_tpid;
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
            if(valid){ 
                this.mask = 0xFFFF;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            vlan2_tpid = bb.readShort() & 0xFFFF;
            return this;
        }

        @Override
        public Vlan2_TpidCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Vlan2_TpidCriterion Mask should not be zero");
            }
            return new Vlan2_TpidCriterion(vlan2_tpid, mask);
        }
    }
}
