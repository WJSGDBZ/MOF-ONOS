package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Udp_SourceCriterion implements Criterion {


    private final long udp_source;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return udp_source;
    }
  
    public long mask(){
        return mask;
    }

    public Udp_SourceCriterion(long udp_source) {
        this(udp_source, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param udp_source the Ethernet frame type to match
     */
    public Udp_SourceCriterion(long udp_source, long mask) {
        this.udp_source = udp_source;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)udp_source);
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
        return Type.UDP_SOURCE;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long udp_source() {
        return udp_source;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(udp_source, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), udp_source);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Udp_SourceCriterion) {
            Udp_SourceCriterion that = (Udp_SourceCriterion) obj;
            return udp_source == that.udp_source && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long udp_source;
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
            udp_source = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Udp_SourceCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Udp_SourceCriterion Mask should not be zero");
            }
            return new Udp_SourceCriterion(udp_source, mask);
        }
    }
}
