package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ip_Id_ICriterion implements Criterion {


    private final long ip_id_i;
  	private final long mask;

    public static final int LEN = 2;

    public long value() {
        return ip_id_i;
    }
  
    public long mask(){
        return mask;
    }

    Ip_Id_ICriterion(long ip_id_i) {
        this(ip_id_i, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param ip_id_i the Ethernet frame type to match
     */
    Ip_Id_ICriterion(long ip_id_i, long mask) {
        this.ip_id_i = ip_id_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)ip_id_i);
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
        return Type.IP_ID_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ip_id_i() {
        return ip_id_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ip_id_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ip_id_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ip_Id_ICriterion) {
            Ip_Id_ICriterion that = (Ip_Id_ICriterion) obj;
            return ip_id_i == that.ip_id_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ip_id_i;
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
            ip_id_i = bb.readShort() & 0xFFFFL;
            return this;
        }

        @Override
        public Ip_Id_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ip_Id_ICriterion Mask should not be zero");
            }
            return new Ip_Id_ICriterion(ip_id_i, mask);
        }
    }
}
