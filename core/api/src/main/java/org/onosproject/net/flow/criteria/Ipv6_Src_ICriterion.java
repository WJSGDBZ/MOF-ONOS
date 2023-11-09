package org.onosproject.net.flow.criteria;

import org.onlab.packet.Ipv6_Src_I;

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv6_Src_ICriterion implements Criterion {


    private final Ipv6_Src_I ipv6_src_i;
  	private final Ipv6_Src_I mask;

    public static final int LEN = 16;

    Ipv6_Src_ICriterion(Ipv6_Src_I ipv6_src_i) {
        byte[] ones = new byte[Ipv6_Src_I.LEN];
        Arrays.fill(ones, (byte) 0xFF);
        Ipv6_Src_I mask_full_one = Ipv6_Src_I.valueOf(ones);
        this.ipv6_src_i = ipv6_src_i;
        this.mask = mask_full_one;
    }

    /**
     * Constructor.
     *
     * @param ipv6_src_i the Ethernet frame type to match
     */
    Ipv6_Src_ICriterion(Ipv6_Src_I ipv6_src_i, Ipv6_Src_I mask) {
        this.ipv6_src_i = ipv6_src_i;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        byte[] data = ipv6_src_i.toBytes();
        for (int i = 0; i < data.length; i++) {
            bb.writeByte(data[i]);
        }
    }

    @Override
    public void writeMask(ByteBuf bb){
        byte[] data = mask.toBytes();
        for (int i = 0; i < data.length; i++) {
            bb.writeByte(data[i]);
        }
    }

    public static void writeZero(ByteBuf bb){
        bb.writeZero(16);
    }

    @Override
    public Type type() {
        return Type.IPV6_SRC_I;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public Ipv6_Src_I ipv6_src_i() {
        return ipv6_src_i;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.ComplexParser(ipv6_src_i.toBytes(), mask.toBytes(), type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv6_src_i);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_Src_ICriterion) {
            Ipv6_Src_ICriterion that = (Ipv6_Src_ICriterion) obj;
            return ipv6_src_i.equals(that.ipv6_src_i) && mask.equals(that.mask);
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private Ipv6_Src_I ipv6_src_i;
        private Ipv6_Src_I mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            byte[] mask = new byte[LEN];
            valid_mask = false;
            for(int i = 0; i < LEN; i++){
                byte b = bb.readByte();
                if(b != (byte)0x0){
                    valid_mask = true;
                }
                mask[i] = b;
            }
            if(valid_mask)
                this.mask = Ipv6_Src_I.valueOf(mask);

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            byte[] data = new byte[LEN];
            bb.readBytes(data);
            this.ipv6_src_i = Ipv6_Src_I.valueOf(data);
            return this;
        }

        @Override
        public Ipv6_Src_ICriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv6_Src_ICriterion Mask should not be zero");
            }
            return new Ipv6_Src_ICriterion(ipv6_src_i, mask);
        }
    }
}
