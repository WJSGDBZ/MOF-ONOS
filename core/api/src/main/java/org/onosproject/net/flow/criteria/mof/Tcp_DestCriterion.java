package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Tcp_DestCriterion implements Criterion {


    private final long tcp_dest;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return tcp_dest;
    }
  
    public long mask(){
        return mask;
    }

    Tcp_DestCriterion(long tcp_dest) {
        this(tcp_dest, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param tcp_dest the Ethernet frame type to match
     */
    Tcp_DestCriterion(long tcp_dest, long mask) {
        this.tcp_dest = tcp_dest;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)tcp_dest);
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
        return Type.TCP_DEST;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long tcp_dest() {
        return tcp_dest;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(tcp_dest, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), tcp_dest);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Tcp_DestCriterion) {
            Tcp_DestCriterion that = (Tcp_DestCriterion) obj;
            return tcp_dest == that.tcp_dest && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long tcp_dest;
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
            tcp_dest = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Tcp_DestCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Tcp_DestCriterion Mask should not be zero");
            }
            return new Tcp_DestCriterion(tcp_dest, mask);
        }
    }
}
