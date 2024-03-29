package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ip_Daddr_ECriterion implements Criterion {


    private final long ip_daddr_e;
  	private final long mask;

    public static final int LEN = 4;

    public long value() {
        return ip_daddr_e;
    }
  
    public long mask(){
        return mask;
    }

    public Ip_Daddr_ECriterion(long ip_daddr_e) {
        this(ip_daddr_e, 0xFFFFFFFF);
    }

    /**
     * Constructor.
     *
     * @param ip_daddr_e the Ethernet frame type to match
     */
    public Ip_Daddr_ECriterion(long ip_daddr_e, long mask) {
        this.ip_daddr_e = ip_daddr_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeInt((int)ip_daddr_e);
    }

    @Override
    public void writeMask(ByteBuf bb){
        bb.writeInt((int)mask);
    }

    public static void writeZero(ByteBuf bb){
        bb.writeZero(4);
    }

    @Override
    public Type type() {
        return Type.IP_DADDR_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ip_daddr_e() {
        return ip_daddr_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ip_daddr_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ip_daddr_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ip_Daddr_ECriterion) {
            Ip_Daddr_ECriterion that = (Ip_Daddr_ECriterion) obj;
            return ip_daddr_e == that.ip_daddr_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ip_daddr_e;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readInt() & 0xFFFFFFFFL;
            if(mask != 0){
                valid_mask = true;
            }

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                this.mask = 0xFFFFFFFFL;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            ip_daddr_e = bb.readInt() & 0xFFFFFFFFL;
            return this;
        }

        @Override
        public Ip_Daddr_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ip_Daddr_ECriterion Mask should not be zero");
            }
            return new Ip_Daddr_ECriterion(ip_daddr_e, mask);
        }
    }
}
