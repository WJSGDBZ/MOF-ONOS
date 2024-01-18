package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ip_Check_ICriterion implements Criterion {


    private final long ip_check_i;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return ip_check_i;
    }
  
    public long mask(){
        return mask;
    }

    public Ip_Check_ICriterion(long ip_check_i) {
        this(ip_check_i, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param ip_check_i the Ethernet frame type to match
     */
    public Ip_Check_ICriterion(long ip_check_i, long mask) {
        this.ip_check_i = ip_check_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)ip_check_i);
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
        return Type.IP_CHECK_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ip_check_i() {
        return ip_check_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ip_check_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ip_check_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ip_Check_ICriterion) {
            Ip_Check_ICriterion that = (Ip_Check_ICriterion) obj;
            return ip_check_i == that.ip_check_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ip_check_i;
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
            ip_check_i = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Ip_Check_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ip_Check_ICriterion Mask should not be zero");
            }
            return new Ip_Check_ICriterion(ip_check_i, mask);
        }
    }
}
