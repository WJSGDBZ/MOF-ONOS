package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Srv6_TypeCriterion implements Criterion {


    private final long srv6_type;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return srv6_type;
    }
  
    public long mask(){
        return mask;
    }

    Srv6_TypeCriterion(long srv6_type) {
        this(srv6_type, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param srv6_type the Ethernet frame type to match
     */
    Srv6_TypeCriterion(long srv6_type, long mask) {
        this.srv6_type = srv6_type;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)srv6_type);
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
        return Type.SRV6_TYPE;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long srv6_type() {
        return srv6_type;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(srv6_type, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), srv6_type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Srv6_TypeCriterion) {
            Srv6_TypeCriterion that = (Srv6_TypeCriterion) obj;
            return srv6_type == that.srv6_type && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long srv6_type;
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
            srv6_type = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Srv6_TypeCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Srv6_TypeCriterion Mask should not be zero");
            }
            return new Srv6_TypeCriterion(srv6_type, mask);
        }
    }
}
