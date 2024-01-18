package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Udp_CheckCriterion implements Criterion {


    private final long udp_check;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return udp_check;
    }
  
    public long mask(){
        return mask;
    }

    public Udp_CheckCriterion(long udp_check) {
        this(udp_check, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param udp_check the Ethernet frame type to match
     */
    public Udp_CheckCriterion(long udp_check, long mask) {
        this.udp_check = udp_check;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)udp_check);
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
        return Type.UDP_CHECK;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long udp_check() {
        return udp_check;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(udp_check, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), udp_check);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Udp_CheckCriterion) {
            Udp_CheckCriterion that = (Udp_CheckCriterion) obj;
            return udp_check == that.udp_check && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long udp_check;
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
            udp_check = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Udp_CheckCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Udp_CheckCriterion Mask should not be zero");
            }
            return new Udp_CheckCriterion(udp_check, mask);
        }
    }
}
