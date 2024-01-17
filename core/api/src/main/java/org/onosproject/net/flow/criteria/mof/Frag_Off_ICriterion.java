package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Frag_Off_ICriterion implements Criterion {


    private final long frag_off_i;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return frag_off_i;
    }
  
    public long mask(){
        return mask;
    }

    Frag_Off_ICriterion(long frag_off_i) {
        this(frag_off_i, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param frag_off_i the Ethernet frame type to match
     */
    Frag_Off_ICriterion(long frag_off_i, long mask) {
        this.frag_off_i = frag_off_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)frag_off_i);
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
        return Type.FRAG_OFF_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long frag_off_i() {
        return frag_off_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(frag_off_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), frag_off_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Frag_Off_ICriterion) {
            Frag_Off_ICriterion that = (Frag_Off_ICriterion) obj;
            return frag_off_i == that.frag_off_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long frag_off_i;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readShort() & 0xFFFFL;
            if(mask != 0){
                valid_mask = true;
            }

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                this.mask = 0xFFFFL;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            frag_off_i = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Frag_Off_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Frag_Off_ICriterion Mask should not be zero");
            }
            return new Frag_Off_ICriterion(frag_off_i, mask);
        }
    }
}
