package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv4_E_TypeCriterion implements Criterion {


    private final long ipv4_e_type;
  	private final long mask;

    public static final int LEN = 1;

    Ipv4_E_TypeCriterion(long ipv4_e_type) {
        this(ipv4_e_type, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param ipv4_e_type the Ethernet frame type to match
     */
    Ipv4_E_TypeCriterion(long ipv4_e_type, long mask) {
        this.ipv4_e_type = ipv4_e_type;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)ipv4_e_type);
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
        return Type.IPV4_E_TYPE;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ipv4_e_type() {
        return ipv4_e_type;
    }

    public long value(){
        return ipv4_e_type;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ipv4_e_type, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv4_e_type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv4_E_TypeCriterion) {
            Ipv4_E_TypeCriterion that = (Ipv4_E_TypeCriterion) obj;
            return ipv4_e_type == that.ipv4_e_type && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ipv4_e_type;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readByte();
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
            ipv4_e_type = bb.readByte();
            return this;
        }

        @Override
        public Ipv4_E_TypeCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv4_E_TypeCriterion Mask should not be zero");
            }
            return new Ipv4_E_TypeCriterion(ipv4_e_type, mask);
        }
    }
}
