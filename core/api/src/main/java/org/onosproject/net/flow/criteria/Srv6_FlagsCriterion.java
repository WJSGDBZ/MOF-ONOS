package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Srv6_FlagsCriterion implements Criterion {


    private final long srv6_flags;
  	private final long mask;

    public static final int LEN = 1;

    Srv6_FlagsCriterion(long srv6_flags) {
        this(srv6_flags, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param srv6_flags the Ethernet frame type to match
     */
    Srv6_FlagsCriterion(long srv6_flags, long mask) {
        this.srv6_flags = srv6_flags;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)srv6_flags);
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
        return Type.SRV6_FLAGS;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long srv6_flags() {
        return srv6_flags;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(srv6_flags, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), srv6_flags);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Srv6_FlagsCriterion) {
            Srv6_FlagsCriterion that = (Srv6_FlagsCriterion) obj;
            return srv6_flags == that.srv6_flags && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long srv6_flags;
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
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            srv6_flags = bb.readByte();
            return this;
        }

        @Override
        public Srv6_FlagsCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Srv6_FlagsCriterion Mask should not be zero");
            }
            return new Srv6_FlagsCriterion(srv6_flags, mask);
        }
    }
}
