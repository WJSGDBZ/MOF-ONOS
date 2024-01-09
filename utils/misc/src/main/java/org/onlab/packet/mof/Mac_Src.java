package org.onlab.packet;

import com.google.common.collect.ImmutableSet;
import java.util.Arrays;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Mac_Src {
  
  	public static final int LEN = 6;
    private byte[] mac_src = new byte[LEN];

    public Mac_Src(final byte[] field) {
        this.mac_src = Arrays.copyOf(field, LEN);
    }
  
    public static Mac_Src valueOf(final byte[] field) {
        if (field.length > LEN) {
            throw new IllegalArgumentException("Mac_Src valueOf out of the bound should " + 
                                                LEN + "get " + field.length);
        }

        return new Mac_Src(field);
    }
  
    public int length() {
        return this.mac_src.length;
    }
  
    public byte[] toBytes() {
        return Arrays.copyOf(this.mac_src, this.mac_src.length);
    }
  	
  	@Override
    public boolean equals(final Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof Mac_Src)) {
            return false;
        }

        final Mac_Src other = (Mac_Src) o;
        return Arrays.equals(this.mac_src, other.mac_src);
    }

  	@Override
    public int hashCode() {
        return (int)mac_src[0];
    }
		
    @Override
    public String toString() {
      return encodeHexString();
    }
    
    
    public String encodeHexString() {
        StringBuilder sb = new StringBuilder();
        for (byte b : this.mac_src) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
