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

import org.onosproject.net.flow.instructions.protocol.Tcp_Protocol;
import org.onosproject.net.flow.instructions.protocol.Udp_Protocol;
import org.onosproject.net.flow.instructions.protocol.Srv6_1_Protocol;
import org.onosproject.net.flow.instructions.protocol.Srv6_2_Protocol;
import org.onosproject.net.flow.instructions.protocol.Srv6_3_Protocol;

public class MOFL4Layer extends BasePacket {
    private Tcp_Protocol tcp;
    private Udp_Protocol udp;
    private Srv6_1_Protocol srv6_1;
    private Srv6_2_Protocol srv6_2;
    private Srv6_3_Protocol srv6_3;
    private int LEN = 0;
    private int nextType = -1;
    
    /**
     * By default, set MOFL4Layer to untagged.
    */
    public MOFL4Layer() {
        super();
    }

    public int Length(){
        return LEN;
    }

    public boolean isTcp_Protocol(){
        return tcp != null;
    }
    public boolean isUdp_Protocol(){
        return udp != null;
    }
    public boolean isSrv6_1_Protocol(){
        return srv6_1 != null;
    }
    public boolean isSrv6_2_Protocol(){
        return srv6_2 != null;
    }
    public boolean isSrv6_3_Protocol(){
        return srv6_3 != null;
    }

    public static MOFL4Layer parse(int type, byte[] data, int offset){
        MOFL4Layer l4 = new MOFL4Layer();
        int length = data.length - offset;
        if(Specific_Protocol.getInstance().contains(type)){
            Specific_Protocol.getInstance().parse_specific_protocolL4(type, Unpooled.wrappedBuffer(data, offset, length), l4);
        }else{
            switch (type) {
            case 0x00:
                l4.setTcp_Protocol(Tcp_Protocol.read(Unpooled.wrappedBuffer(data, offset, length)));
                break;
            case 0x11:
                l4.setUdp_Protocol(Udp_Protocol.read(Unpooled.wrappedBuffer(data, offset, length)));
                break;
            default:
                throw new UnsupportedOperationException("L4Layer type is unsupported");
            }
        }

        return l4;
    }

    public int getNextType(){
        return nextType;
    }

    public void setTcp_Protocol(Tcp_Protocol tcp){
        this.tcp = tcp;
        this.nextType = -1;
        this.LEN = Tcp_Protocol.LEN;
    }
 
    public Tcp_Protocol getTcp_Protocol(){
        checkNotNull(tcp, "get Tcp_Protocol value is null");
        return tcp;
    }

    public void setUdp_Protocol(Udp_Protocol udp){
        this.udp = udp;
        this.nextType = -1;
        this.LEN = Udp_Protocol.LEN;
    }
 
    public Udp_Protocol getUdp_Protocol(){
        checkNotNull(udp, "get Udp_Protocol value is null");
        return udp;
    }

    public void setSrv6_1_Protocol(Srv6_1_Protocol srv6_1){
        this.srv6_1 = srv6_1;
        this.nextType = (int)srv6_1.srv6_type.value();
        this.LEN = Srv6_1_Protocol.LEN;
    }
 
    public Srv6_1_Protocol getSrv6_1_Protocol(){
        checkNotNull(srv6_1, "get Srv6_1_Protocol value is null");
        return srv6_1;
    }

    public void setSrv6_2_Protocol(Srv6_2_Protocol srv6_2){
        this.srv6_2 = srv6_2;
        this.nextType = (int)srv6_2.srv6_type.value();
        this.LEN = Srv6_2_Protocol.LEN;
    }
 
    public Srv6_2_Protocol getSrv6_2_Protocol(){
        checkNotNull(srv6_2, "get Srv6_2_Protocol value is null");
        return srv6_2;
    }

    public void setSrv6_3_Protocol(Srv6_3_Protocol srv6_3){
        this.srv6_3 = srv6_3;
        this.nextType = (int)srv6_3.srv6_type.value();
        this.LEN = Srv6_3_Protocol.LEN;
    }
 
    public Srv6_3_Protocol getSrv6_3_Protocol(){
        checkNotNull(srv6_3, "get Srv6_3_Protocol value is null");
        return srv6_3;
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
        if(tcp != null){
            return tcp.hashCode();
        }
        if(udp != null){
            return udp.hashCode();
        }
        if(srv6_1 != null){
            return srv6_1.hashCode();
        }
        if(srv6_2 != null){
            return srv6_2.hashCode();
        }
        if(srv6_3 != null){
            return srv6_3.hashCode();
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
        if(tcp != null){
            return Objects.equals(tcp, obj);
        }
        if(udp != null){
            return Objects.equals(udp, obj);
        }
        if(srv6_1 != null){
            return Objects.equals(srv6_1, obj);
        }
        if(srv6_2 != null){
            return Objects.equals(srv6_2, obj);
        }
        if(srv6_3 != null){
            return Objects.equals(srv6_3, obj);
        }

        return super.equals(obj);
    }
}
