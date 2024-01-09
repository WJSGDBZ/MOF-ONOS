package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Srv6_Routing_TypeCriterion implements Criterion {


    private final long srv6_routing_Type;
  	private final long mask;

    public static final int LEN = 1;

    public long value() {
        return srv6_routing_Type;
    }
  
    public long mask(){
        return mask;
    }

    Srv6_Routing_TypeCriterion(long srv6_routing_Type) {
        this(srv6_routing_Type, 0xFF);
    }

    /**
     * Constructor.
     *
     * @param srv6_routing_Type the Ethernet frame type to match
     */
    Srv6_Routing_TypeCriterion(long srv6_routing_Type, long mask) {
        this.srv6_routing_Type = srv6_routing_Type;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeByte((byte)srv6_routing_Type);
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
        return Type.SRV6_ROUTING_TYPE;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long srv6_routing_Type() {
        return srv6_routing_Type;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(srv6_routing_Type, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), srv6_routing_Type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Srv6_Routing_TypeCriterion) {
            Srv6_Routing_TypeCriterion that = (Srv6_Routing_TypeCriterion) obj;
            return srv6_routing_Type == that.srv6_routing_Type && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long srv6_routing_Type;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readByte();
            if(mask != 0){
                valid_mask = true;
            }

            return valid_mask;
        }

        @Override
        public Builder setValid(boolean valid){
            valid_mask = valid;
            if(valid){ 
                this.mask = 0xFF;
            }
            return this;
        }

        @Override
        public Builder readData(ByteBuf bb){
            srv6_routing_Type = bb.readByte() & 0xFF;
            return this;
        }

        @Override
        public Srv6_Routing_TypeCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Srv6_Routing_TypeCriterion Mask should not be zero");
            }
            return new Srv6_Routing_TypeCriterion(srv6_routing_Type, mask);
        }
    }
}
