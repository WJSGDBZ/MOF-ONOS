package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ver_Hl_ICriterion implements Criterion {


    private final long ver_hl_i;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return ver_hl_i;
    }
  
    public long mask(){
        return mask;
    }

    Ver_Hl_ICriterion(long ver_hl_i) {
        this(ver_hl_i, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param ver_hl_i the Ethernet frame type to match
     */
    Ver_Hl_ICriterion(long ver_hl_i, long mask) {
        this.ver_hl_i = ver_hl_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)ver_hl_i);
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
        return Type.VER_HL_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ver_hl_i() {
        return ver_hl_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ver_hl_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ver_hl_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ver_Hl_ICriterion) {
            Ver_Hl_ICriterion that = (Ver_Hl_ICriterion) obj;
            return ver_hl_i == that.ver_hl_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ver_hl_i;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readByte();
            if(mask != 0){
                valid_mask = true;
            }

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                this.mask = 0xFF;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            ver_hl_i = bb.readByte() & 0xFF;
            return this;
        }

        @Override
        public Ver_Hl_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ver_Hl_ICriterion Mask should not be zero");
            }
            return new Ver_Hl_ICriterion(ver_hl_i, mask);
        }
    }
}
