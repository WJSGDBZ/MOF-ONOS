package org.onosproject.net.flow.criteria;

import org.onlab.packet.Ipv6_Src_E;

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ipv6_Src_ECriterion implements Criterion {


    private final Ipv6_Src_E ipv6_src_e;
  	private final Ipv6_Src_E mask;

    public static final int LEN = 16;

    public Ipv6_Src_E value() {
        return ipv6_src_e;
    }
  
    public Ipv6_Src_E mask(){
        return mask;
    }

    Ipv6_Src_ECriterion(Ipv6_Src_E ipv6_src_e) {
        byte[] ones = new byte[Ipv6_Src_E.LEN];
        Arrays.fill(ones, (byte) 0xFF);
        Ipv6_Src_E mask_full_one = Ipv6_Src_E.valueOf(ones);
        this.ipv6_src_e = ipv6_src_e;
        this.mask = mask_full_one;
    }

    /**
     * Constructor.
     *
     * @param ipv6_src_e the Ethernet frame type to match
     */
    Ipv6_Src_ECriterion(Ipv6_Src_E ipv6_src_e, Ipv6_Src_E mask) {
        this.ipv6_src_e = ipv6_src_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        byte[] data = ipv6_src_e.toBytes();
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
        return Type.IPV6_SRC_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public Ipv6_Src_E ipv6_src_e() {
        return ipv6_src_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.ComplexParser(ipv6_src_e.toBytes(), mask.toBytes(), type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ipv6_src_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ipv6_Src_ECriterion) {
            Ipv6_Src_ECriterion that = (Ipv6_Src_ECriterion) obj;
            return ipv6_src_e.equals(that.ipv6_src_e) && mask.equals(that.mask);
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private Ipv6_Src_E ipv6_src_e;
        private Ipv6_Src_E mask;
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
                this.mask = Ipv6_Src_E.valueOf(mask);

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                byte[] ALL = new byte[LEN];
                Arrays.fill(ALL, (byte) 0xFF);
                this.mask = Ipv6_Src_E.valueOf(ALL);
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            byte[] data = new byte[LEN];
            bb.readBytes(data);
            this.ipv6_src_e = Ipv6_Src_E.valueOf(data);
            return this;
        }

        @Override
        public Ipv6_Src_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ipv6_Src_ECriterion Mask should not be zero");
            }
            return new Ipv6_Src_ECriterion(ipv6_src_e, mask);
        }
    }
}
