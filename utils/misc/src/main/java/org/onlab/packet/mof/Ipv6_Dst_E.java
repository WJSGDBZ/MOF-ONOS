package org.onlab.packet;

import com.google.common.collect.ImmutableSet;
import java.util.Arrays;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Ipv6_Dst_E {
  
  	public static final int LEN = 16;
    private byte[] ipv6_dst_e = new byte[LEN];

    public Ipv6_Dst_E(final byte[] field) {
        this.ipv6_dst_e = Arrays.copyOf(field, LEN);
    }
  
    public static Ipv6_Dst_E valueOf(final byte[] field) {
        if (field.length > LEN) {
            throw new IllegalArgumentException("Ipv6_Dst_E valueOf out of the bound should " + 
                                                LEN + "get " + field.length);
        }

        return new Ipv6_Dst_E(field);
    }
  
    public int length() {
        return this.ipv6_dst_e.length;
    }
  
    public byte[] toBytes() {
        return Arrays.copyOf(this.ipv6_dst_e, this.ipv6_dst_e.length);
    }
  	
  	@Override
    public boolean equals(final Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof Ipv6_Dst_E)) {
            return false;
        }

        final Ipv6_Dst_E other = (Ipv6_Dst_E) o;
        return Arrays.equals(this.ipv6_dst_e, other.ipv6_dst_e);
    }

  	@Override
    public int hashCode() {
        return (int)ipv6_dst_e[0];
    }
		
    @Override
    public String toString() {
      return encodeHexString();
    }
    
    
    public String encodeHexString() {
        StringBuilder sb = new StringBuilder();
        for (byte b : this.ipv6_dst_e) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
