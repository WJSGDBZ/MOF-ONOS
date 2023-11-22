package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Urg_PtrCriterion implements Criterion {


    private final long urg_ptr;
  	private final long mask;

    public static final int LEN = 2;

    Urg_PtrCriterion(long urg_ptr) {
        this(urg_ptr, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param urg_ptr the Ethernet frame type to match
     */
    Urg_PtrCriterion(long urg_ptr, long mask) {
        this.urg_ptr = urg_ptr;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)urg_ptr);
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
        return Type.URG_PTR;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long urg_ptr() {
        return urg_ptr;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(urg_ptr, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), urg_ptr);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Urg_PtrCriterion) {
            Urg_PtrCriterion that = (Urg_PtrCriterion) obj;
            return urg_ptr == that.urg_ptr && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long urg_ptr;
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
            urg_ptr = bb.readShort();
            return this;
        }

        @Override
        public Urg_PtrCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Urg_PtrCriterion Mask should not be zero");
            }
            return new Urg_PtrCriterion(urg_ptr, mask);
        }
    }
}
