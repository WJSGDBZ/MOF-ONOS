package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Srv6_Segments_LeftCriterion implements Criterion {


    private final long srv6_segments_left;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return srv6_segments_left;
    }
  
    public long mask(){
        return mask;
    }

    Srv6_Segments_LeftCriterion(long srv6_segments_left) {
        this(srv6_segments_left, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param srv6_segments_left the Ethernet frame type to match
     */
    Srv6_Segments_LeftCriterion(long srv6_segments_left, long mask) {
        this.srv6_segments_left = srv6_segments_left;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)srv6_segments_left);
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
        return Type.SRV6_SEGMENTS_LEFT;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long srv6_segments_left() {
        return srv6_segments_left;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(srv6_segments_left, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), srv6_segments_left);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Srv6_Segments_LeftCriterion) {
            Srv6_Segments_LeftCriterion that = (Srv6_Segments_LeftCriterion) obj;
            return srv6_segments_left == that.srv6_segments_left && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long srv6_segments_left;
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
            srv6_segments_left = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Srv6_Segments_LeftCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Srv6_Segments_LeftCriterion Mask should not be zero");
            }
            return new Srv6_Segments_LeftCriterion(srv6_segments_left, mask);
        }
    }
}
