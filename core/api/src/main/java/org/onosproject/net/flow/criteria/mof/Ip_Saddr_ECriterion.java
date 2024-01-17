package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ip_Saddr_ECriterion implements Criterion {


    private final long ip_saddr_e;
  	private final long mask;

    public static final int LEN = 4;

    public long value() {
        return ip_saddr_e;
    }
  
    public long mask(){
        return mask;
    }

    Ip_Saddr_ECriterion(long ip_saddr_e) {
        this(ip_saddr_e, 0xFFFFFFFF);
    }

    /**
     * Constructor.
     *
     * @param ip_saddr_e the Ethernet frame type to match
     */
    Ip_Saddr_ECriterion(long ip_saddr_e, long mask) {
        this.ip_saddr_e = ip_saddr_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeInt((int)ip_saddr_e);
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
        return Type.IP_SADDR_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ip_saddr_e() {
        return ip_saddr_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ip_saddr_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ip_saddr_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ip_Saddr_ECriterion) {
            Ip_Saddr_ECriterion that = (Ip_Saddr_ECriterion) obj;
            return ip_saddr_e == that.ip_saddr_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ip_saddr_e;
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
            ip_saddr_e = bb.readInt() & 0xFFFFFFFFL;
            return this;
        }

        @Override
        public Ip_Saddr_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ip_Saddr_ECriterion Mask should not be zero");
            }
            return new Ip_Saddr_ECriterion(ip_saddr_e, mask);
        }
    }
}
