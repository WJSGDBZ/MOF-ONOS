package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Off_BitsCriterion implements Criterion {


    private final long off_bits;
  	private final long mask;

    public static final int LEN = 2;

    Off_BitsCriterion(long off_bits) {
        this(off_bits, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param off_bits the Ethernet frame type to match
     */
    Off_BitsCriterion(long off_bits, long mask) {
        this.off_bits = off_bits;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)off_bits);
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
        return Type.OFF_BITS;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long off_bits() {
        return off_bits;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(off_bits, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), off_bits);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Off_BitsCriterion) {
            Off_BitsCriterion that = (Off_BitsCriterion) obj;
            return off_bits == that.off_bits && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long off_bits;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readShort();
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
            off_bits = bb.readShort();
            return this;
        }

        @Override
        public Off_BitsCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Off_BitsCriterion Mask should not be zero");
            }
            return new Off_BitsCriterion(off_bits, mask);
        }
    }
}
