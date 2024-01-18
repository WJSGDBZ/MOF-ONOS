package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class LenCriterion implements Criterion {


    private final long len;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return len;
    }
  
    public long mask(){
        return mask;
    }

    public LenCriterion(long len) {
        this(len, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param len the Ethernet frame type to match
     */
    public LenCriterion(long len, long mask) {
        this.len = len;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)len);
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
        return Type.LEN;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long len() {
        return len;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(len, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), len);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof LenCriterion) {
            LenCriterion that = (LenCriterion) obj;
            return len == that.len && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long len;
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
            len = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public LenCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("LenCriterion Mask should not be zero");
            }
            return new LenCriterion(len, mask);
        }
    }
}
