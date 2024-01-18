package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ttl_ECriterion implements Criterion {


    private final long ttl_e;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return ttl_e;
    }
  
    public long mask(){
        return mask;
    }

    public Ttl_ECriterion(long ttl_e) {
        this(ttl_e, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param ttl_e the Ethernet frame type to match
     */
    public Ttl_ECriterion(long ttl_e, long mask) {
        this.ttl_e = ttl_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)ttl_e);
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
        return Type.TTL_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ttl_e() {
        return ttl_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ttl_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ttl_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ttl_ECriterion) {
            Ttl_ECriterion that = (Ttl_ECriterion) obj;
            return ttl_e == that.ttl_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ttl_e;
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
            ttl_e = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Ttl_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ttl_ECriterion Mask should not be zero");
            }
            return new Ttl_ECriterion(ttl_e, mask);
        }
    }
}
