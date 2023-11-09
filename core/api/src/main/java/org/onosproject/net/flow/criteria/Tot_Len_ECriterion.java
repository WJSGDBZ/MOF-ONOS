package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Tot_Len_ECriterion implements Criterion {


    private final long tot_len_e;
  	private final long mask;

    public static final int LEN = 2;

    Tot_Len_ECriterion(long tot_len_e) {
        this(tot_len_e, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param tot_len_e the Ethernet frame type to match
     */
    Tot_Len_ECriterion(long tot_len_e, long mask) {
        this.tot_len_e = tot_len_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)tot_len_e);
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
        return Type.TOT_LEN_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long tot_len_e() {
        return tot_len_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(tot_len_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), tot_len_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Tot_Len_ECriterion) {
            Tot_Len_ECriterion that = (Tot_Len_ECriterion) obj;
            return tot_len_e == that.tot_len_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long tot_len_e;
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
            tot_len_e = bb.readShort();
            return this;
        }

        @Override
        public Tot_Len_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Tot_Len_ECriterion Mask should not be zero");
            }
            return new Tot_Len_ECriterion(tot_len_e, mask);
        }
    }
}
