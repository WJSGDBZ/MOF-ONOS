package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Tos_ICriterion implements Criterion {


    private final long tos_i;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return tos_i;
    }
  
    public long mask(){
        return mask;
    }

    Tos_ICriterion(long tos_i) {
        this(tos_i, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param tos_i the Ethernet frame type to match
     */
    Tos_ICriterion(long tos_i, long mask) {
        this.tos_i = tos_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)tos_i);
    }

    @Override
    public void writeMask(ByteBuf bb){
        bb.writeByte((byte)mask);
    }

    public static void writeZero(ByteBuf bb){
        bb.writeZero(1);
    }

    @Override
    public Type type() {
        return Type.TOS_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long tos_i() {
        return tos_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(tos_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), tos_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Tos_ICriterion) {
            Tos_ICriterion that = (Tos_ICriterion) obj;
            return tos_i == that.tos_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long tos_i;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readByte() & 0xFFL;
            if(mask != 0){
                valid_mask = true;
            }

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                this.mask = 0xFFL;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            tos_i = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Tos_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Tos_ICriterion Mask should not be zero");
            }
            return new Tos_ICriterion(tos_i, mask);
        }
    }
}
