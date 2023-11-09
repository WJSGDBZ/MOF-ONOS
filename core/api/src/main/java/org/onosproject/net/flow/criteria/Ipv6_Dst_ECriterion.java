package org.onosproject.net.flow.criteria;

import org.onlab.packet.Ipv6_Dst_E;

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv6_Dst_ECriterion implements Criterion {


    private final Ipv6_Dst_E ipv6_dst_e;
  	private final Ipv6_Dst_E mask;

    public static final int LEN = 16;

    Ipv6_Dst_ECriterion(Ipv6_Dst_E ipv6_dst_e) {
        byte[] ones = new byte[Ipv6_Dst_E.LEN];
        Arrays.fill(ones, (byte) 0xFF);
        Ipv6_Dst_E mask_full_one = Ipv6_Dst_E.valueOf(ones);
        this.ipv6_dst_e = ipv6_dst_e;
        this.mask = mask_full_one;
    }

    /**
     * Constructor.
     *
     * @param ipv6_dst_e the Ethernet frame type to match
     */
    Ipv6_Dst_ECriterion(Ipv6_Dst_E ipv6_dst_e, Ipv6_Dst_E mask) {
        this.ipv6_dst_e = ipv6_dst_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        byte[] data = ipv6_dst_e.toBytes();
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
        return Type.IPV6_DST_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public Ipv6_Dst_E ipv6_dst_e() {
        return ipv6_dst_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.ComplexParser(ipv6_dst_e.toBytes(), mask.toBytes(), type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv6_dst_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_Dst_ECriterion) {
            Ipv6_Dst_ECriterion that = (Ipv6_Dst_ECriterion) obj;
            return ipv6_dst_e.equals(that.ipv6_dst_e) && mask.equals(that.mask);
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private Ipv6_Dst_E ipv6_dst_e;
        private Ipv6_Dst_E mask;
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
                this.mask = Ipv6_Dst_E.valueOf(mask);

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
            this.ipv6_dst_e = Ipv6_Dst_E.valueOf(data);
            return this;
        }

        @Override
        public Ipv6_Dst_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv6_Dst_ECriterion Mask should not be zero");
            }
            return new Ipv6_Dst_ECriterion(ipv6_dst_e, mask);
        }
    }
}
