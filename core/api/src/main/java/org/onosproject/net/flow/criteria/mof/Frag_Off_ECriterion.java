package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Frag_Off_ECriterion implements Criterion {


    private final long frag_off_e;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return frag_off_e;
    }
  
    public long mask(){
        return mask;
    }

    public Frag_Off_ECriterion(long frag_off_e) {
        this(frag_off_e, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param frag_off_e the Ethernet frame type to match
     */
    public Frag_Off_ECriterion(long frag_off_e, long mask) {
        this.frag_off_e = frag_off_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)frag_off_e);
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
        return Type.FRAG_OFF_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long frag_off_e() {
        return frag_off_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(frag_off_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), frag_off_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Frag_Off_ECriterion) {
            Frag_Off_ECriterion that = (Frag_Off_ECriterion) obj;
            return frag_off_e == that.frag_off_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long frag_off_e;
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
            frag_off_e = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Frag_Off_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Frag_Off_ECriterion Mask should not be zero");
            }
            return new Frag_Off_ECriterion(frag_off_e, mask);
        }
    }
}
