package org.onosproject.net.flow.criteria;

import org.onlab.packet.Srv6_Segmentlist2;

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Srv6_Segmentlist2Criterion implements Criterion {


    private final Srv6_Segmentlist2 srv6_segmentlist2;
  	private final Srv6_Segmentlist2 mask;

    public static final int LEN = 16;

    public Srv6_Segmentlist2 value() {
        return srv6_segmentlist2;
    }
  
    public Srv6_Segmentlist2 mask(){
        return mask;
    }

    public Srv6_Segmentlist2Criterion(Srv6_Segmentlist2 srv6_segmentlist2) {
        byte[] ones = new byte[Srv6_Segmentlist2.LEN];
        Arrays.fill(ones, (byte) 0xFF);
        Srv6_Segmentlist2 mask_full_one = Srv6_Segmentlist2.valueOf(ones);
        this.srv6_segmentlist2 = srv6_segmentlist2;
        this.mask = mask_full_one;
    }

    /**
     * Constructor.
     *
     * @param srv6_segmentlist2 the Ethernet frame type to match
     */
    public Srv6_Segmentlist2Criterion(Srv6_Segmentlist2 srv6_segmentlist2, Srv6_Segmentlist2 mask) {
        this.srv6_segmentlist2 = srv6_segmentlist2;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        byte[] data = srv6_segmentlist2.toBytes();
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
        return Type.SRV6_SEGMENTLIST2;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public Srv6_Segmentlist2 srv6_segmentlist2() {
        return srv6_segmentlist2;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.ComplexParser(srv6_segmentlist2.toBytes(), mask.toBytes(), type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), srv6_segmentlist2);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Srv6_Segmentlist2Criterion) {
            Srv6_Segmentlist2Criterion that = (Srv6_Segmentlist2Criterion) obj;
            return srv6_segmentlist2.equals(that.srv6_segmentlist2) && mask.equals(that.mask);
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private Srv6_Segmentlist2 srv6_segmentlist2;
        private Srv6_Segmentlist2 mask;
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
                this.mask = Srv6_Segmentlist2.valueOf(mask);

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                byte[] ALL = new byte[LEN];
                Arrays.fill(ALL, (byte) 0xFF);
                this.mask = Srv6_Segmentlist2.valueOf(ALL);
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            byte[] data = new byte[LEN];
            bb.readBytes(data);
            this.srv6_segmentlist2 = Srv6_Segmentlist2.valueOf(data);
            return this;
        }

        @Override
        public Srv6_Segmentlist2Criterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Srv6_Segmentlist2Criterion Mask should not be zero");
            }
            return new Srv6_Segmentlist2Criterion(srv6_segmentlist2, mask);
        }
    }
}
