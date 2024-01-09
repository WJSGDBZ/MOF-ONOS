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

import org.onosproject.net.flow.instructions.protocol.Ipv4_E_Protocol;
import org.onosproject.net.flow.instructions.protocol.Ipv6_E_Protocol;

public class MOFL3Layer extends BasePacket {
    private Ipv4_E_Protocol ipv4_e;
    private Ipv6_E_Protocol ipv6_e;
    private int LEN = 0;
    private int nextType = -1;
    
    /**
     * By default, set MOFL3Layer to untagged.
    */
    public MOFL3Layer() {
        super();
    }

    public int Length(){
        return LEN;
    }

    public boolean isIpv4_E_Protocol(){
        return ipv4_e != null;
    }
    public boolean isIpv6_E_Protocol(){
        return ipv6_e != null;
    }

    public static MOFL3Layer parse(int type, byte[] data, int offset){
        MOFL3Layer l3 = new MOFL3Layer();
        int length = data.length - offset;
        if(Specific_Protocol.getInstance().contains(type)){
            Specific_Protocol.getInstance().parse_specific_protocolL3(type, Unpooled.wrappedBuffer(data, offset, length), l3);
        }else{
            switch (type) {
            case 0x0800:
                l3.setIpv4_E_Protocol(Ipv4_E_Protocol.read(Unpooled.wrappedBuffer(data, offset, length)));
                break;
            case 0x86DD:
                l3.setIpv6_E_Protocol(Ipv6_E_Protocol.read(Unpooled.wrappedBuffer(data, offset, length)));
                break;
            default:
                throw new UnsupportedOperationException("L3Layer type is unsupported");
            }
        }

        return l3;
    }

    public int getNextType(){
        return nextType;
    }

    public void setIpv4_E_Protocol(Ipv4_E_Protocol ipv4_e){
        this.ipv4_e = ipv4_e;
        this.nextType = (int)ipv4_e.ipv4_e_type.value();
        this.LEN = Ipv4_E_Protocol.LEN;
    }
 
    public Ipv4_E_Protocol getIpv4_E_Protocol(){
        checkNotNull(ipv4_e, "get Ipv4_E_Protocol value is null");
        return ipv4_e;
    }

    public void setIpv6_E_Protocol(Ipv6_E_Protocol ipv6_e){
        this.ipv6_e = ipv6_e;
        this.nextType = (int)ipv6_e.ipv6_e_type.value();
        this.LEN = Ipv6_E_Protocol.LEN;
    }
 
    public Ipv6_E_Protocol getIpv6_E_Protocol(){
        checkNotNull(ipv6_e, "get Ipv6_E_Protocol value is null");
        return ipv6_e;
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
        if(ipv4_e != null){
            return ipv4_e.hashCode();
        }
        if(ipv6_e != null){
            return ipv6_e.hashCode();
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
        if(ipv4_e != null){
            return Objects.equals(ipv4_e, obj);
        }
        if(ipv6_e != null){
            return Objects.equals(ipv6_e, obj);
        }

        return super.equals(obj);
    }
}
