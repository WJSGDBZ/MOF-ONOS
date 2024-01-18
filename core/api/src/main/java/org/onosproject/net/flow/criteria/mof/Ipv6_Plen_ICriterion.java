package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv6_Plen_ICriterion implements Criterion {


    private final long ipv6_plen_i;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return ipv6_plen_i;
    }
  
    public long mask(){
        return mask;
    }

    public Ipv6_Plen_ICriterion(long ipv6_plen_i) {
        this(ipv6_plen_i, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param ipv6_plen_i the Ethernet frame type to match
     */
    public Ipv6_Plen_ICriterion(long ipv6_plen_i, long mask) {
        this.ipv6_plen_i = ipv6_plen_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)ipv6_plen_i);
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
        return Type.IPV6_PLEN_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ipv6_plen_i() {
        return ipv6_plen_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ipv6_plen_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv6_plen_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_Plen_ICriterion) {
            Ipv6_Plen_ICriterion that = (Ipv6_Plen_ICriterion) obj;
            return ipv6_plen_i == that.ipv6_plen_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ipv6_plen_i;
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
            ipv6_plen_i = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Ipv6_Plen_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv6_Plen_ICriterion Mask should not be zero");
            }
            return new Ipv6_Plen_ICriterion(ipv6_plen_i, mask);
        }
    }
}
