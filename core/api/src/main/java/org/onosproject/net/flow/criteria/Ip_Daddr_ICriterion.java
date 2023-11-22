package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ip_Daddr_ICriterion implements Criterion {


    private final long ip_daddr_i;
  	private final long mask;

    public static final int LEN = 4;

    Ip_Daddr_ICriterion(long ip_daddr_i) {
        this(ip_daddr_i, 0xFFFFFFFF);
    }

    /**
     * Constructor.
     *
     * @param ip_daddr_i the Ethernet frame type to match
     */
    Ip_Daddr_ICriterion(long ip_daddr_i, long mask) {
        this.ip_daddr_i = ip_daddr_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeInt((int)ip_daddr_i);
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
        return Type.IP_DADDR_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ip_daddr_i() {
        return ip_daddr_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ip_daddr_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ip_daddr_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ip_Daddr_ICriterion) {
            Ip_Daddr_ICriterion that = (Ip_Daddr_ICriterion) obj;
            return ip_daddr_i == that.ip_daddr_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ip_daddr_i;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readInt();
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
            ip_daddr_i = bb.readInt();
            return this;
        }

        @Override
        public Ip_Daddr_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ip_Daddr_ICriterion Mask should not be zero");
            }
            return new Ip_Daddr_ICriterion(ip_daddr_i, mask);
        }
    }
}
