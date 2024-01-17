package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv6_Ver_Tp_Flb_ICriterion implements Criterion {


    private final long ipv6_ver_tp_flb_i;
  	private final long mask;

    public static final int LEN = 4;

    public long value() {
        return ipv6_ver_tp_flb_i;
    }
  
    public long mask(){
        return mask;
    }

    Ipv6_Ver_Tp_Flb_ICriterion(long ipv6_ver_tp_flb_i) {
        this(ipv6_ver_tp_flb_i, 0xFFFFFFFF);
    }

    /**
     * Constructor.
     *
     * @param ipv6_ver_tp_flb_i the Ethernet frame type to match
     */
    Ipv6_Ver_Tp_Flb_ICriterion(long ipv6_ver_tp_flb_i, long mask) {
        this.ipv6_ver_tp_flb_i = ipv6_ver_tp_flb_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeInt((int)ipv6_ver_tp_flb_i);
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
        return Type.IPV6_VER_TP_FLB_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ipv6_ver_tp_flb_i() {
        return ipv6_ver_tp_flb_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ipv6_ver_tp_flb_i, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv6_ver_tp_flb_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_Ver_Tp_Flb_ICriterion) {
            Ipv6_Ver_Tp_Flb_ICriterion that = (Ipv6_Ver_Tp_Flb_ICriterion) obj;
            return ipv6_ver_tp_flb_i == that.ipv6_ver_tp_flb_i && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ipv6_ver_tp_flb_i;
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
            ipv6_ver_tp_flb_i = bb.readInt() & 0xFFFFFFFFL;
            return this;
        }

        @Override
        public Ipv6_Ver_Tp_Flb_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv6_Ver_Tp_Flb_ICriterion Mask should not be zero");
            }
            return new Ipv6_Ver_Tp_Flb_ICriterion(ipv6_ver_tp_flb_i, mask);
        }
    }
}
