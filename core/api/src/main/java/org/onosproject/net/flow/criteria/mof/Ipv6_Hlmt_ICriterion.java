package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv6_Hlmt_ICriterion implements Criterion {


    private final long ipv6_hlmt_i;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return ipv6_hlmt_i;
    }
  
    public long mask(){
        return mask;
    }

    public Ipv6_Hlmt_ICriterion(long ipv6_hlmt_i) {
        this(ipv6_hlmt_i, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param ipv6_hlmt_i the Ethernet frame type to match
     */
    public Ipv6_Hlmt_ICriterion(long ipv6_hlmt_i, long mask) {
        this.ipv6_hlmt_i = ipv6_hlmt_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)ipv6_hlmt_i);
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
        return Type.IPV6_HLMT_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ipv6_hlmt_i() {
        return ipv6_hlmt_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ipv6_hlmt_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv6_hlmt_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_Hlmt_ICriterion) {
            Ipv6_Hlmt_ICriterion that = (Ipv6_Hlmt_ICriterion) obj;
            return ipv6_hlmt_i == that.ipv6_hlmt_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ipv6_hlmt_i;
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
            ipv6_hlmt_i = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Ipv6_Hlmt_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv6_Hlmt_ICriterion Mask should not be zero");
            }
            return new Ipv6_Hlmt_ICriterion(ipv6_hlmt_i, mask);
        }
    }
}
