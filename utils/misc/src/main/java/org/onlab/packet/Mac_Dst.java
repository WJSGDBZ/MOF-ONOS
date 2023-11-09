package org.onlab.packet;

import com.google.common.collect.ImmutableSet;
import java.util.Arrays;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Mac_Dst {
  
  	public static final int LEN = 6;
    private byte[] mac_dst = new byte[LEN];

    public Mac_Dst(final byte[] field) {
        this.mac_dst = Arrays.copyOf(field, LEN);
    }
  
    public static Mac_Dst valueOf(final byte[] field) {
        if (field.length > LEN) {
            throw new IllegalArgumentException("Mac_Dst valueOf out of the bound should " + 
                                                LEN + "get " + field.length);
        }

        return new Mac_Dst(field);
    }
  
    public int length() {
        return this.mac_dst.length;
    }
  
    public byte[] toBytes() {
        return Arrays.copyOf(this.mac_dst, this.mac_dst.length);
    }
  	
  	@Override
    public boolean equals(final Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof Mac_Dst)) {
            return false;
        }

        final Mac_Dst other = (Mac_Dst) o;
        return Arrays.equals(this.mac_dst, other.mac_dst);
    }

  	@Override
    public int hashCode() {
        return (int)mac_dst[0];
    }
		
    @Override
    public String toString() {
      return encodeHexString();
    }
    
    
    public String encodeHexString() {
        StringBuilder sb = new StringBuilder();
        for (byte b : this.mac_dst) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
