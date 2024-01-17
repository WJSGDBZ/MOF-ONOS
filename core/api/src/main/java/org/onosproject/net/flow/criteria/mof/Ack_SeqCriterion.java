package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ack_SeqCriterion implements Criterion {


    private final long ack_seq;
  	private final long mask;

    public static final int LEN = 4;

    public long value() {
        return ack_seq;
    }
  
    public long mask(){
        return mask;
    }

    Ack_SeqCriterion(long ack_seq) {
        this(ack_seq, 0xFFFFFFFF);
    }

    /**
     * Constructor.
     *
     * @param ack_seq the Ethernet frame type to match
     */
    Ack_SeqCriterion(long ack_seq, long mask) {
        this.ack_seq = ack_seq;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeInt((int)ack_seq);
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
        return Type.ACK_SEQ;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ack_seq() {
        return ack_seq;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ack_seq, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ack_seq);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ack_SeqCriterion) {
            Ack_SeqCriterion that = (Ack_SeqCriterion) obj;
            return ack_seq == that.ack_seq && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ack_seq;
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
            ack_seq = bb.readInt() & 0xFFFFFFFFL;
            return this;
        }

        @Override
        public Ack_SeqCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ack_SeqCriterion Mask should not be zero");
            }
            return new Ack_SeqCriterion(ack_seq, mask);
        }
    }
}
