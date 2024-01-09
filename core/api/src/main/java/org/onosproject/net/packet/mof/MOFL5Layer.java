/*
 * Copyright 2014-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.onosproject.net.packet.mof;


import org.onlab.packet.BasePacket;
import java.util.Objects;
import static com.google.common.base.Preconditions.checkNotNull;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.onosproject.net.flow.instructions.protocol.Specific_Protocol;

import org.onosproject.net.flow.instructions.protocol.Ipv6_I_Protocol;
import org.onosproject.net.flow.instructions.protocol.Ipv4_I_Protocol;

public class MOFL5Layer extends BasePacket {
    private Ipv6_I_Protocol ipv6_i;
    private Ipv4_I_Protocol ipv4_i;
    private int LEN = 0;
    private int nextType = -1;
    
    /**
     * By default, set MOFL5Layer to untagged.
    */
    public MOFL5Layer() {
        super();
    }

    public int Length(){
        return LEN;
    }

    public boolean isIpv6_I_Protocol(){
        return ipv6_i != null;
    }
    public boolean isIpv4_I_Protocol(){
        return ipv4_i != null;
    }

    public static MOFL5Layer parse(int type, byte[] data, int offset){
        MOFL5Layer l5 = new MOFL5Layer();
        int length = data.length - offset;
        if(Specific_Protocol.getInstance().contains(type)){
            Specific_Protocol.getInstance().parse_specific_protocolL5(type, Unpooled.wrappedBuffer(data, offset, length), l5);
        }else{
            switch (type) {
            case 0x29:
                l5.setIpv6_I_Protocol(Ipv6_I_Protocol.read(Unpooled.wrappedBuffer(data, offset, length)));
                break;
            case 0x00:
                l5.setIpv4_I_Protocol(Ipv4_I_Protocol.read(Unpooled.wrappedBuffer(data, offset, length)));
                break;
            default:
                throw new UnsupportedOperationException("L5Layer type is unsupported");
            }
        }

        return l5;
    }

    public int getNextType(){
        return nextType;
    }

    public void setIpv6_I_Protocol(Ipv6_I_Protocol ipv6_i){
        this.ipv6_i = ipv6_i;
        this.nextType = (int)ipv6_i.ipv6_i_type.value();
        this.LEN = Ipv6_I_Protocol.LEN;
    }
 
    public Ipv6_I_Protocol getIpv6_I_Protocol(){
        checkNotNull(ipv6_i, "get Ipv6_I_Protocol value is null");
        return ipv6_i;
    }

    public void setIpv4_I_Protocol(Ipv4_I_Protocol ipv4_i){
        this.ipv4_i = ipv4_i;
        this.nextType = (int)ipv4_i.ipv4_i_type.value();
        this.LEN = Ipv4_I_Protocol.LEN;
    }
 
    public Ipv4_I_Protocol getIpv4_I_Protocol(){
        checkNotNull(ipv4_i, "get Ipv4_I_Protocol value is null");
        return ipv4_i;
    }

    @Override
    public byte[] serialize() {
        return null;
    }

    /*
    * (non-Javadoc)
    *
    * @see java.lang.Object#hashCode()
    */
    @Override
    public int hashCode() {
        if(ipv6_i != null){
            return ipv6_i.hashCode();
        }
        if(ipv4_i != null){
            return ipv4_i.hashCode();
        }

        return super.hashCode();
    }

    /*
    * (non-Javadoc)
    *
    * @see java.lang.Object#equals(java.lang.Object)
    */
    @Override
    public boolean equals(final Object obj) {
        if(ipv6_i != null){
            return Objects.equals(ipv6_i, obj);
        }
        if(ipv4_i != null){
            return Objects.equals(ipv4_i, obj);
        }

        return super.equals(obj);
    }
}
