package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Srv6_Last_EntyCriterion implements Criterion {


    private final long srv6_last_enty;
  	private final long mask;

    public static final int LEN = 1;

    Srv6_Last_EntyCriterion(long srv6_last_enty) {
        this(srv6_last_enty, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param srv6_last_enty the Ethernet frame type to match
     */
    Srv6_Last_EntyCriterion(long srv6_last_enty, long mask) {
        this.srv6_last_enty = srv6_last_enty;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)srv6_last_enty);
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
        return Type.SRV6_LAST_ENTY;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long srv6_last_enty() {
        return srv6_last_enty;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(srv6_last_enty, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), srv6_last_enty);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Srv6_Last_EntyCriterion) {
            Srv6_Last_EntyCriterion that = (Srv6_Last_EntyCriterion) obj;
            return srv6_last_enty == that.srv6_last_enty && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long srv6_last_enty;
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
            srv6_last_enty = bb.readByte();
            return this;
        }

        @Override
        public Srv6_Last_EntyCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Srv6_Last_EntyCriterion Mask should not be zero");
            }
            return new Srv6_Last_EntyCriterion(srv6_last_enty, mask);
        }
    }
}
