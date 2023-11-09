package org.onlab.packet;

import com.google.common.collect.ImmutableSet;
import java.util.Arrays;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Ipv6_Dst_I {
  
  	public static final int LEN = 16;
    private byte[] ipv6_dst_i = new byte[LEN];

    public Ipv6_Dst_I(final byte[] field) {
        this.ipv6_dst_i = Arrays.copyOf(field, LEN);
    }
  
    public static Ipv6_Dst_I valueOf(final byte[] field) {
        if (field.length > LEN) {
            throw new IllegalArgumentException("Ipv6_Dst_I valueOf out of the bound should " + 
                                                LEN + "get " + field.length);
        }

        return new Ipv6_Dst_I(field);
    }
  
    public int length() {
        return this.ipv6_dst_i.length;
    }
  
    public byte[] toBytes() {
        return Arrays.copyOf(this.ipv6_dst_i, this.ipv6_dst_i.length);
    }
  	
  	@Override
    public boolean equals(final Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof Ipv6_Dst_I)) {
            return false;
        }

        final Ipv6_Dst_I other = (Ipv6_Dst_I) o;
        return Arrays.equals(this.ipv6_dst_i, other.ipv6_dst_i);
    }

  	@Override
    public int hashCode() {
        return (int)ipv6_dst_i[0];
    }
		
    @Override
    public String toString() {
      return encodeHexString();
    }
    
    
    public String encodeHexString() {
        StringBuilder sb = new StringBuilder();
        for (byte b : this.ipv6_dst_i) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
