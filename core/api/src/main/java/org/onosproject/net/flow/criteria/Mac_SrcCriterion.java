package org.onosproject.net.flow.criteria;

import org.onlab.packet.Mac_Src;

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Mac_SrcCriterion implements Criterion {


    private final Mac_Src mac_src;
  	private final Mac_Src mask;

    public static final int LEN = 6;

    Mac_SrcCriterion(Mac_Src mac_src) {
        byte[] ones = new byte[Mac_Src.LEN];
        Arrays.fill(ones, (byte) 0xFF);
        Mac_Src mask_full_one = Mac_Src.valueOf(ones);
        this.mac_src = mac_src;
        this.mask = mask_full_one;
    }

    /**
     * Constructor.
     *
     * @param mac_src the Ethernet frame type to match
     */
    Mac_SrcCriterion(Mac_Src mac_src, Mac_Src mask) {
        this.mac_src = mac_src;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        byte[] data = mac_src.toBytes();
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
        return Type.MAC_SRC;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public Mac_Src mac_src() {
        return mac_src;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.ComplexParser(mac_src.toBytes(), mask.toBytes(), type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), mac_src);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Mac_SrcCriterion) {
            Mac_SrcCriterion that = (Mac_SrcCriterion) obj;
            return mac_src.equals(that.mac_src) && mask.equals(that.mask);
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private Mac_Src mac_src;
        private Mac_Src mask;
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
                this.mask = Mac_Src.valueOf(mask);

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
            this.mac_src = Mac_Src.valueOf(data);
            return this;
        }

        @Override
        public Mac_SrcCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Mac_SrcCriterion Mask should not be zero");
            }
            return new Mac_SrcCriterion(mac_src, mask);
        }
    }
}
