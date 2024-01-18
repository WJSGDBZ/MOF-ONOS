package org.onosproject.net.flow.criteria;

import org.onlab.packet.Mac_Dst;

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Mac_DstCriterion implements Criterion {


    private final Mac_Dst mac_dst;
  	private final Mac_Dst mask;

    public static final int LEN = 6;

    public Mac_Dst value() {
        return mac_dst;
    }
  
    public Mac_Dst mask(){
        return mask;
    }

    public Mac_DstCriterion(Mac_Dst mac_dst) {
        byte[] ones = new byte[Mac_Dst.LEN];
        Arrays.fill(ones, (byte) 0xFF);
        Mac_Dst mask_full_one = Mac_Dst.valueOf(ones);
        this.mac_dst = mac_dst;
        this.mask = mask_full_one;
    }

    /**
     * Constructor.
     *
     * @param mac_dst the Ethernet frame type to match
     */
    public Mac_DstCriterion(Mac_Dst mac_dst, Mac_Dst mask) {
        this.mac_dst = mac_dst;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        byte[] data = mac_dst.toBytes();
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
        bb.writeZero(6);
    }

    @Override
    public Type type() {
        return Type.MAC_DST;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public Mac_Dst mac_dst() {
        return mac_dst;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.ComplexParser(mac_dst.toBytes(), mask.toBytes(), type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), mac_dst);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Mac_DstCriterion) {
            Mac_DstCriterion that = (Mac_DstCriterion) obj;
            return mac_dst.equals(that.mac_dst) && mask.equals(that.mask);
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private Mac_Dst mac_dst;
        private Mac_Dst mask;
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
                this.mask = Mac_Dst.valueOf(mask);

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                byte[] ALL = new byte[LEN];
                Arrays.fill(ALL, (byte) 0xFF);
                this.mask = Mac_Dst.valueOf(ALL);
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            byte[] data = new byte[LEN];
            bb.readBytes(data);
            this.mac_dst = Mac_Dst.valueOf(data);
            return this;
        }

        @Override
        public Mac_DstCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Mac_DstCriterion Mask should not be zero");
            }
            return new Mac_DstCriterion(mac_dst, mask);
        }
    }
}
