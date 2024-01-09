package org.onlab.packet;

import com.google.common.collect.ImmutableSet;
import java.util.Arrays;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Srv6_Segmentlist3 {
  
  	public static final int LEN = 16;
    private byte[] srv6_segmentlist3 = new byte[LEN];

    public Srv6_Segmentlist3(final byte[] field) {
        this.srv6_segmentlist3 = Arrays.copyOf(field, LEN);
    }
  
    public static Srv6_Segmentlist3 valueOf(final byte[] field) {
        if (field.length > LEN) {
            throw new IllegalArgumentException("Srv6_Segmentlist3 valueOf out of the bound should " + 
                                                LEN + "get " + field.length);
        }

        return new Srv6_Segmentlist3(field);
    }
  
    public int length() {
        return this.srv6_segmentlist3.length;
    }
  
    public byte[] toBytes() {
        return Arrays.copyOf(this.srv6_segmentlist3, this.srv6_segmentlist3.length);
    }
  	
  	@Override
    public boolean equals(final Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof Srv6_Segmentlist3)) {
            return false;
        }

        final Srv6_Segmentlist3 other = (Srv6_Segmentlist3) o;
        return Arrays.equals(this.srv6_segmentlist3, other.srv6_segmentlist3);
    }

  	@Override
    public int hashCode() {
        return (int)srv6_segmentlist3[0];
    }
		
    @Override
    public String toString() {
      return encodeHexString();
    }
    
    
    public String encodeHexString() {
        StringBuilder sb = new StringBuilder();
        for (byte b : this.srv6_segmentlist3) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
