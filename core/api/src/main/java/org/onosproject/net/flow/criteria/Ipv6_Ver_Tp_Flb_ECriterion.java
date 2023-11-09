package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv6_Ver_Tp_Flb_ECriterion implements Criterion {


    private final long ipv6_ver_tp_flb_e;
  	private final long mask;

    public static final int LEN = 4;

    Ipv6_Ver_Tp_Flb_ECriterion(long ipv6_ver_tp_flb_e) {
        this(ipv6_ver_tp_flb_e, 0xFFFFFFFF);
    }

    /**
     * Constructor.
     *
     * @param ipv6_ver_tp_flb_e the Ethernet frame type to match
     */
    Ipv6_Ver_Tp_Flb_ECriterion(long ipv6_ver_tp_flb_e, long mask) {
        this.ipv6_ver_tp_flb_e = ipv6_ver_tp_flb_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeInt((int)ipv6_ver_tp_flb_e);
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
        return Type.IPV6_VER_TP_FLB_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ipv6_ver_tp_flb_e() {
        return ipv6_ver_tp_flb_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ipv6_ver_tp_flb_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv6_ver_tp_flb_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_Ver_Tp_Flb_ECriterion) {
            Ipv6_Ver_Tp_Flb_ECriterion that = (Ipv6_Ver_Tp_Flb_ECriterion) obj;
            return ipv6_ver_tp_flb_e == that.ipv6_ver_tp_flb_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ipv6_ver_tp_flb_e;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readInt();
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
            ipv6_ver_tp_flb_e = bb.readInt();
            return this;
        }

        @Override
        public Ipv6_Ver_Tp_Flb_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv6_Ver_Tp_Flb_ECriterion Mask should not be zero");
            }
            return new Ipv6_Ver_Tp_Flb_ECriterion(ipv6_ver_tp_flb_e, mask);
        }
    }
}
