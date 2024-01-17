package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ttl_ICriterion implements Criterion {


    private final long ttl_i;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return ttl_i;
    }
  
    public long mask(){
        return mask;
    }

    Ttl_ICriterion(long ttl_i) {
        this(ttl_i, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param ttl_i the Ethernet frame type to match
     */
    Ttl_ICriterion(long ttl_i, long mask) {
        this.ttl_i = ttl_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)ttl_i);
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
        return Type.TTL_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ttl_i() {
        return ttl_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ttl_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ttl_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ttl_ICriterion) {
            Ttl_ICriterion that = (Ttl_ICriterion) obj;
            return ttl_i == that.ttl_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ttl_i;
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
            ttl_i = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Ttl_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ttl_ICriterion Mask should not be zero");
            }
            return new Ttl_ICriterion(ttl_i, mask);
        }
    }
}
