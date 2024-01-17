package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv6_Hlmt_ECriterion implements Criterion {


    private final long ipv6_hlmt_e;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return ipv6_hlmt_e;
    }
  
    public long mask(){
        return mask;
    }

    Ipv6_Hlmt_ECriterion(long ipv6_hlmt_e) {
        this(ipv6_hlmt_e, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param ipv6_hlmt_e the Ethernet frame type to match
     */
    Ipv6_Hlmt_ECriterion(long ipv6_hlmt_e, long mask) {
        this.ipv6_hlmt_e = ipv6_hlmt_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)ipv6_hlmt_e);
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
        return Type.IPV6_HLMT_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ipv6_hlmt_e() {
        return ipv6_hlmt_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ipv6_hlmt_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv6_hlmt_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_Hlmt_ECriterion) {
            Ipv6_Hlmt_ECriterion that = (Ipv6_Hlmt_ECriterion) obj;
            return ipv6_hlmt_e == that.ipv6_hlmt_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ipv6_hlmt_e;
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
            ipv6_hlmt_e = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Ipv6_Hlmt_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv6_Hlmt_ECriterion Mask should not be zero");
            }
            return new Ipv6_Hlmt_ECriterion(ipv6_hlmt_e, mask);
        }
    }
}
