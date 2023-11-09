package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class Ip_Id_ECriterion implements Criterion {


    private final long ip_id_e;
  	private final long mask;

    public static final int LEN = 2;

    Ip_Id_ECriterion(long ip_id_e) {
        this(ip_id_e, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param ip_id_e the Ethernet frame type to match
     */
    Ip_Id_ECriterion(long ip_id_e, long mask) {
        this.ip_id_e = ip_id_e;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)ip_id_e);
    }

    @Override
    public void writeMask(ByteBuf bb){
        bb.writeShort((short)mask);
    }

    public static void writeZero(ByteBuf bb){
        bb.writeZero(2);
    }

    @Override
    public Type type() {
        return Type.IP_ID_E;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long ip_id_e() {
        return ip_id_e;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(ip_id_e, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), ip_id_e);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Ip_Id_ECriterion) {
            Ip_Id_ECriterion that = (Ip_Id_ECriterion) obj;
            return ip_id_e == that.ip_id_e && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long ip_id_e;
        private long mask;
        private boolean valid_mask;

        @Override
        public boolean readMask(ByteBuf bb){
            mask = bb.readShort();
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
            ip_id_e = bb.readShort();
            return this;
        }

        @Override
        public Ip_Id_ECriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("Ip_Id_ECriterion Mask should not be zero");
            }
            return new Ip_Id_ECriterion(ip_id_e, mask);
        }
    }
}
