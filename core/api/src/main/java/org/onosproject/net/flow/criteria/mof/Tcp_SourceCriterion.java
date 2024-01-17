package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Tcp_SourceCriterion implements Criterion {


    private final long tcp_source;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return tcp_source;
    }
  
    public long mask(){
        return mask;
    }

    Tcp_SourceCriterion(long tcp_source) {
        this(tcp_source, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param tcp_source the Ethernet frame type to match
     */
    Tcp_SourceCriterion(long tcp_source, long mask) {
        this.tcp_source = tcp_source;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)tcp_source);
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
        return Type.TCP_SOURCE;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long tcp_source() {
        return tcp_source;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(tcp_source, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), tcp_source);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Tcp_SourceCriterion) {
            Tcp_SourceCriterion that = (Tcp_SourceCriterion) obj;
            return tcp_source == that.tcp_source && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long tcp_source;
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
            tcp_source = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Tcp_SourceCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Tcp_SourceCriterion Mask should not be zero");
            }
            return new Tcp_SourceCriterion(tcp_source, mask);
        }
    }
}
