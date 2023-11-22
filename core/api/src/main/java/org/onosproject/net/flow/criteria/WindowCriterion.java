package org.onosproject.net.flow.criteria;

 

import io.netty.buffer.ByteBuf;

import java.util.Objects;

import java.util.Arrays;

import org.onosproject.net.flow.criteria.parser.*;

public final class WindowCriterion implements Criterion {


    private final long window;
  	private final long mask;

    public static final int LEN = 2;

    WindowCriterion(long window) {
        this(window, 0xFFFF);
    }

    /**
     * Constructor.
     *
     * @param window the Ethernet frame type to match
     */
    WindowCriterion(long window, long mask) {
        this.window = window;
      	this.mask = mask;
    }

  	@Override
    public void write(ByteBuf bb){
        bb.writeShort((short)window);
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
        return Type.WINDOW;
    }

    /**
     * Gets the Ethernet frame type to match.
     *
     * @return the Ethernet frame type to match (16 bits unsigned integer)
     */
    public long window() {
        return window;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + CriterionParser.BasicParser(window, mask, type());
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), window);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof WindowCriterion) {
            WindowCriterion that = (WindowCriterion) obj;
            return window == that.window && mask == that.mask;
        }
        return false;
    }

    public static class Builder implements Criterion.Builder {
        private long window;
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
            window = bb.readShort();
            return this;
        }

        @Override
        public WindowCriterion build(){
            if(!valid_mask){
                throw new IllegalArgumentException("WindowCriterion Mask should not be zero");
            }
            return new WindowCriterion(window, mask);
        }
    }
}
