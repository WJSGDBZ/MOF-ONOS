package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv6_E_TypeCriterion implements Criterion {


    private final long ipv6_e_type;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return ipv6_e_type;
    }
  
    public long mask(){
        return mask;
    }

    Ipv6_E_TypeCriterion(long ipv6_e_type) {
        this(ipv6_e_type, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param ipv6_e_type the Ethernet frame type to match
     */
    Ipv6_E_TypeCriterion(long ipv6_e_type, long mask) {
        this.ipv6_e_type = ipv6_e_type;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)ipv6_e_type);
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
        return Type.IPV6_E_TYPE;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ipv6_e_type() {
        return ipv6_e_type;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ipv6_e_type, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv6_e_type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_E_TypeCriterion) {
            Ipv6_E_TypeCriterion that = (Ipv6_E_TypeCriterion) obj;
            return ipv6_e_type == that.ipv6_e_type && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ipv6_e_type;
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
            ipv6_e_type = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Ipv6_E_TypeCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv6_E_TypeCriterion Mask should not be zero");
            }
            return new Ipv6_E_TypeCriterion(ipv6_e_type, mask);
        }
    }
}
