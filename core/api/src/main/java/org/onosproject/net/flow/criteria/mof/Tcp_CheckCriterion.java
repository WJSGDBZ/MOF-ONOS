package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Tcp_CheckCriterion implements Criterion {


    private final long tcp_check;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return tcp_check;
    }
  
    public long mask(){
        return mask;
    }

    Tcp_CheckCriterion(long tcp_check) {
        this(tcp_check, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param tcp_check the Ethernet frame type to match
     */
    Tcp_CheckCriterion(long tcp_check, long mask) {
        this.tcp_check = tcp_check;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)tcp_check);
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
        return Type.TCP_CHECK;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long tcp_check() {
        return tcp_check;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(tcp_check, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), tcp_check);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Tcp_CheckCriterion) {
            Tcp_CheckCriterion that = (Tcp_CheckCriterion) obj;
            return tcp_check == that.tcp_check && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long tcp_check;
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
            tcp_check = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Tcp_CheckCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Tcp_CheckCriterion Mask should not be zero");
            }
            return new Tcp_CheckCriterion(tcp_check, mask);
        }
    }
}
