package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Srv6_TagCriterion implements Criterion {


    private final long srv6_tag;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return srv6_tag;
    }
  
    public long mask(){
        return mask;
    }

    Srv6_TagCriterion(long srv6_tag) {
        this(srv6_tag, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param srv6_tag the Ethernet frame type to match
     */
    Srv6_TagCriterion(long srv6_tag, long mask) {
        this.srv6_tag = srv6_tag;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)srv6_tag);
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
        return Type.SRV6_TAG;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long srv6_tag() {
        return srv6_tag;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(srv6_tag, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), srv6_tag);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Srv6_TagCriterion) {
            Srv6_TagCriterion that = (Srv6_TagCriterion) obj;
            return srv6_tag == that.srv6_tag && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long srv6_tag;
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
            srv6_tag = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Srv6_TagCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Srv6_TagCriterion Mask should not be zero");
            }
            return new Srv6_TagCriterion(srv6_tag, mask);
        }
    }
}
