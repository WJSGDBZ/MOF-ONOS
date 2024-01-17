package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Srv6_Hdr_Ext_LenCriterion implements Criterion {


    private final long srv6_hdr_ext_len;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return srv6_hdr_ext_len;
    }
  
    public long mask(){
        return mask;
    }

    Srv6_Hdr_Ext_LenCriterion(long srv6_hdr_ext_len) {
        this(srv6_hdr_ext_len, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param srv6_hdr_ext_len the Ethernet frame type to match
     */
    Srv6_Hdr_Ext_LenCriterion(long srv6_hdr_ext_len, long mask) {
        this.srv6_hdr_ext_len = srv6_hdr_ext_len;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)srv6_hdr_ext_len);
    }

    @Override
    public void writeMask(ByteBuf bb){
        bb.writeByte((byte)mask);
    }

    public static void writeZero(ByteBuf bb){
        bb.writeZero(1);
    }

    @Override
    public Type type() {
        return Type.SRV6_HDR_EXT_LEN;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long srv6_hdr_ext_len() {
        return srv6_hdr_ext_len;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(srv6_hdr_ext_len, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), srv6_hdr_ext_len);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Srv6_Hdr_Ext_LenCriterion) {
            Srv6_Hdr_Ext_LenCriterion that = (Srv6_Hdr_Ext_LenCriterion) obj;
            return srv6_hdr_ext_len == that.srv6_hdr_ext_len && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long srv6_hdr_ext_len;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readByte() & 0xFFL;
            if(mask != 0){
                valid_mask = true;
            }

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                this.mask = 0xFFL;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            srv6_hdr_ext_len = bb.readByte() & 0xFFL;
            return this;
        }

        @Override
        public Srv6_Hdr_Ext_LenCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Srv6_Hdr_Ext_LenCriterion Mask should not be zero");
            }
            return new Srv6_Hdr_Ext_LenCriterion(srv6_hdr_ext_len, mask);
        }
    }
}
