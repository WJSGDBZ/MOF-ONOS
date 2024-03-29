package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ip_Check_ECriterion implements Criterion {


    private final long ip_check_e;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return ip_check_e;
    }
  
    public long mask(){
        return mask;
    }

    public Ip_Check_ECriterion(long ip_check_e) {
        this(ip_check_e, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param ip_check_e the Ethernet frame type to match
     */
    public Ip_Check_ECriterion(long ip_check_e, long mask) {
        this.ip_check_e = ip_check_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)ip_check_e);
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
        return Type.IP_CHECK_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ip_check_e() {
        return ip_check_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ip_check_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ip_check_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ip_Check_ECriterion) {
            Ip_Check_ECriterion that = (Ip_Check_ECriterion) obj;
            return ip_check_e == that.ip_check_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ip_check_e;
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
            ip_check_e = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Ip_Check_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ip_Check_ECriterion Mask should not be zero");
            }
            return new Ip_Check_ECriterion(ip_check_e, mask);
        }
    }
}
