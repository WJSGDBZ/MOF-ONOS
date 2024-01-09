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

import static com.google.common.base.Preconditions.checkNotNull;
/**
* MOFFlow Packet.
*/
public class MOFFlow {
    private int parsed_length = 0;
    private MOFL3Layer l3_layer;
    private MOFL4Layer l4_layer;
    private MOFL5Layer l5_layer;

    /**
    * By default, set MOFFlow to untagged.
    */
    public MOFFlow(int offset) {
        parsed_length = offset;
    }

    public void setL3Layer(MOFL3Layer l3){
        this.l3_layer = l3;
    }
    public void setL4Layer(MOFL4Layer l4){
        this.l4_layer = l4;
    }
    public void setL5Layer(MOFL5Layer l5){
        this.l5_layer = l5;
    }
    public MOFL3Layer getL3Layer(){
        checkNotNull(l3_layer, "get MOFL3Layer value is null");
        return l3_layer;
    }
    public MOFL4Layer getL4Layer(){
        checkNotNull(l4_layer, "get MOFL4Layer value is null");
        return l4_layer;
    }
    public MOFL5Layer getL5Layer(){
        checkNotNull(l5_layer, "get MOFL5Layer value is null");
        return l5_layer;
    }

    public void parser(int type, byte[] data){
        int next_type = parseL3(type, data);
        if(next_type != -1){
            next_type = parseL4(next_type, data);
        }
        if(next_type != -1){
            next_type = parseL5(next_type, data);
        }
    }

    private int parseL3(int type, byte[] data){
        MOFL3Layer l3 = MOFL3Layer.parse(type, data, this.parsed_length);
        setL3Layer(l3);

        this.parsed_length += l3.Length();
        return l3.getNextType();
    }

    private int parseL4(int type, byte[] data){
        MOFL4Layer l4 = MOFL4Layer.parse(type, data, this.parsed_length);
        setL4Layer(l4);

        this.parsed_length += l4.Length();
        return l4.getNextType();
    }

    private int parseL5(int type, byte[] data){
        MOFL5Layer l5 = MOFL5Layer.parse(type, data, this.parsed_length);
        setL5Layer(l5);

        this.parsed_length += l5.Length();
        return l5.getNextType();
    }

}