package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Tos_ECriterion implements Criterion {


    private final long tos_e;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return tos_e;
    }
  
    public long mask(){
        return mask;
    }

    public Tos_ECriterion(long tos_e) {
        this(tos_e, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param tos_e the Ethernet frame type to match
     */
    public Tos_ECriterion(long tos_e, long mask) {
        this.tos_e = tos_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)tos_e);
    }

    @Override
    public void writeMask(ByteBuf bb){
        bb.writeByte((byte)mask);
    }

    public static void writeZero(ByteBuf bb){
        bb.writeZero(1);
    }

    @Override
    public Type type() {
        return Type.TOS_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long tos_e() {
        return tos_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(tos_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), tos_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Tos_ECriterion) {
            Tos_ECriterion that = (Tos_ECriterion) obj;
            return tos_e == that.tos_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long tos_e;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readByte() & 0xFFL;
            if(mask != 0){
                valid_mask = true;
            }

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                this.mask = 0xFFL;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            tos_e = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Tos_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Tos_ECriterion Mask should not be zero");
            }
            return new Tos_ECriterion(tos_e, mask);
        }
    }
}
