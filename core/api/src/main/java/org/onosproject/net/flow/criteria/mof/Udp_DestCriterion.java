package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Udp_DestCriterion implements Criterion {


    private final long udp_dest;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return udp_dest;
    }
  
    public long mask(){
        return mask;
    }

    public Udp_DestCriterion(long udp_dest) {
        this(udp_dest, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param udp_dest the Ethernet frame type to match
     */
    public Udp_DestCriterion(long udp_dest, long mask) {
        this.udp_dest = udp_dest;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)udp_dest);
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
        return Type.UDP_DEST;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long udp_dest() {
        return udp_dest;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(udp_dest, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), udp_dest);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Udp_DestCriterion) {
            Udp_DestCriterion that = (Udp_DestCriterion) obj;
            return udp_dest == that.udp_dest && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long udp_dest;
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
            udp_dest = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Udp_DestCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Udp_DestCriterion Mask should not be zero");
            }
            return new Udp_DestCriterion(udp_dest, mask);
        }
    }
}
