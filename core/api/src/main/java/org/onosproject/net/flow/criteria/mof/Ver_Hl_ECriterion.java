package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ver_Hl_ECriterion implements Criterion {


    private final long ver_hl_e;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return ver_hl_e;
    }
  
    public long mask(){
        return mask;
    }

    public Ver_Hl_ECriterion(long ver_hl_e) {
        this(ver_hl_e, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param ver_hl_e the Ethernet frame type to match
     */
    public Ver_Hl_ECriterion(long ver_hl_e, long mask) {
        this.ver_hl_e = ver_hl_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)ver_hl_e);
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
        return Type.VER_HL_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ver_hl_e() {
        return ver_hl_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ver_hl_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ver_hl_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ver_Hl_ECriterion) {
            Ver_Hl_ECriterion that = (Ver_Hl_ECriterion) obj;
            return ver_hl_e == that.ver_hl_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ver_hl_e;
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
            ver_hl_e = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Ver_Hl_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ver_Hl_ECriterion Mask should not be zero");
            }
            return new Ver_Hl_ECriterion(ver_hl_e, mask);
        }
    }
}
