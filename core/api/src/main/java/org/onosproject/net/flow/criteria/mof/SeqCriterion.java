package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class SeqCriterion implements Criterion {


    private final long seq;
  	private final long mask;

    public static final int LEN = 4;

    public long value() {
        return seq;
    }
  
    public long mask(){
        return mask;
    }

    SeqCriterion(long seq) {
        this(seq, 0xFFFFFFFF);
    }

    /**
     * Constructor.
     *
     * @param seq the Ethernet frame type to match
     */
    SeqCriterion(long seq, long mask) {
        this.seq = seq;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeInt((int)seq);
    }

    @Override
    public void writeMask(ByteBuf bb){
        bb.writeInt((int)mask);
    }

    public static void writeZero(ByteBuf bb){
        bb.writeZero(4);
    }

    @Override
    public Type type() {
        return Type.SEQ;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long seq() {
        return seq;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(seq, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), seq);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof SeqCriterion) {
            SeqCriterion that = (SeqCriterion) obj;
            return seq == that.seq && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long seq;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readInt() & 0xFFFFFFFFL;
            if(mask != 0){
                valid_mask = true;
            }

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                this.mask = 0xFFFFFFFFL;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            seq = bb.readInt() & 0xFFFFFFFFL;
            return this;
        }

        @Override
        public SeqCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("SeqCriterion Mask should not be zero");
            }
            return new SeqCriterion(seq, mask);
        }
    }
}
