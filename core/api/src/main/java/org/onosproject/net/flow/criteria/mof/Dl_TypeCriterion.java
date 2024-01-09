package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Dl_TypeCriterion implements Criterion {


    private final long dl_type;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return dl_type;
    }
  
    public long mask(){
        return mask;
    }

    Dl_TypeCriterion(long dl_type) {
        this(dl_type, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param dl_type the Ethernet frame type to match
     */
    Dl_TypeCriterion(long dl_type, long mask) {
        this.dl_type = dl_type;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)dl_type);
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
        return Type.DL_TYPE;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long dl_type() {
        return dl_type;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(dl_type, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), dl_type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Dl_TypeCriterion) {
            Dl_TypeCriterion that = (Dl_TypeCriterion) obj;
            return dl_type == that.dl_type && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long dl_type;
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
            if(valid){ 
                this.mask = 0xFFFF;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            dl_type = bb.readShort() & 0xFFFF;
            return this;
        }

        @Override
        public Dl_TypeCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Dl_TypeCriterion Mask should not be zero");
            }
            return new Dl_TypeCriterion(dl_type, mask);
        }
    }
}
