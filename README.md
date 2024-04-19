# OVS-DPDK
## Description
多协议交换平台基于Openvswitch-DPDK进行设计，交换机的整体架构如图1所示，分为数据包的解析
（Parser），匹配（Match），逆解析（Deparser）三个主要模块，而这三个模块的作用实际上就是数
据包进入到交换平台后要进行的处理流程
![image](https://github.com/WJSGDBZ/MOF-ONOS/assets/50448108/5ae9174f-c14c-401d-98a5-58c3ee4ffefa)
### PHV
在多协议解析中，有多种自定义的协议，以及不同的处理方式，涉及协议类型的添加和删除，为了解决
这种问题，设计了PHV(Protocol Header Vector)。PHV包含所有可能用到的协议头部以及对应的使能
位，协议头部即使用到的协议头部内容，使能位用于指示该协议是否被使用到，置为有效时，即该数据
包（需）含有该协议。
例如，在某包含自定义协议的系统中，使用到了A，B，C，D，E，F共6种协议，包含两种数据包，类型
一为[ABCD(数据)]，类型二为[AEF(数据)]，并且该两种数据包会相互转换，即收到类型一的数据包，需
要转换为类型二发出，如下图所示。
![image](https://github.com/WJSGDBZ/MOF-ONOS/assets/50448108/c4b131e7-1eab-4458-8c2b-63e8c19ac6b4)  
对于这样的系统，PHV的设计为{A, B, E, C, F, D}，即
```
struct PHV {
	// protocol A
	struct A { // 使能位，有效时表示（需）含有该协议头部
		bool enable;
		// 协议A头部各字段
		Atype1 Afield1;
		Atype2 Afield2; ...
	};
	// protocol B
	struct B { // 使能位，有效时表示（需）含有该协议头部
		bool enable;
		// 协议B头部各字段
		Btype1 Bfield1;
		Btype2 Bfield2; ...
	};
	// protocol E
	struct E { // 与上述协议A、B结构相同 ... };
	// protocol C struct C { // 与上述协议A、B结构相同 ... };
	// protocol F
	struct F { // 与上述协议A、B结构相同 ... };
	// protocol D struct D { // 与上述协议A、B结构相同 ... };
};
```
顺序解释如下：在初始情况下，PHV为空，两种数据包最外层的协议头都为协议A，故添加A在第一个位
置，类型一数据包的第二层协议为B（此处的第二层需七层模型的第二层区别开），类型二的数据包第
二层协议为E，则将B, E加入PHV，同理加入协议C, F，最后加入协议D。即下图解析树中由上到下、由左
到右的顺序。  
![image](https://github.com/WJSGDBZ/MOF-ONOS/assets/50448108/7695d51f-8d52-4d74-b1c9-154ed83930ab)  
当接收到一个类型一的数据包时，先建立一个数据该数据包的PHV，所有协议的使能位都为无效。在解
析时就可以发现最外层是协议A，将A的使能位置为有效，在接下来的解析过程中，会依次将B, C, D的使
能位置为有效。此时该PHV指明该数据包含有A, B, C, D四种协议类型头部。在完成匹配后，发现该数据
包需转换为类型二，即包含A, E, F三种协议的新数据包，在执行过程中，会把B, C, D三种协议类型置为
无效，即不需要这几种协议头部，将E, F置为有效，即需要添加这两种协议头部，在逆解析的过程中，就
会按照PHV中的有效位，即A, E, F进行操作。PHV在解析时确定过程如下，蓝色背景表示该协议被置有
效，即enable为true，表示含有该协议。
![image](https://github.com/WJSGDBZ/MOF-ONOS/assets/50448108/d28fc072-42d9-43d9-ac20-d357ac262852)  

# ONOS : Open Network Operating System


## What is ONOS?
ONOS is the only SDN controller platform that supports the transition from
legacy “brown field” networks to SDN “green field” networks. This enables
exciting new capabilities, and disruptive deployment and operational cost points
for network operators.

## Description
这是一个支持多协议版本的ONOS控制器,我将它命名为MOF-ONOS.
通过修改ONOS传输逻辑,北向API, 南向API, restFul接口, 支持额外的匹配域和动作.
支持主动控制和被动控制, 以及用户友好的显示功能.
### 多协议控制器及控制接口
ONOS控制器通过下发流表的方式来告诉OVS如何处理网络报文, 目前主要支持两种方式的下发: 1) 被动下发, 当数据包到达OVS后, OVS匹配不到流表项则会通过packetIn消息向ONOS获取流表. 2) 主动下发, ONOS也可以通过Restful API来主动的向OVS提前配置流表.
#### PacketIn消息介绍
ONOS基于事件触发模型架构, 用户预先定义处理函数, 当收到OVS发送的packetIn消息后会自动调用这个处理函数处理,并下发流表。
原有的packetIn消息只会解析到Mac层,以及一个ByteBuffer格式的payload.也正因为这个限制, 目前ONOS不支持对2层协议的自定义, 默认只支持MAC协议。
取出协议字段
我们在多协议里新增了一个mof_flow字段,他类似于提供一个helper类以帮助开发者进一步解析自定义协议。
```
public final class DefaultInboundPacket implements InboundPacket {
    private final ConnectPoint receivedFrom;
    private final Ethernet parsed;
    private final ByteBuffer unparsed;
    private final Optional<Long> cookie;
    private final MOFFlow mof_flow; // 新增
}
```

可以通过parsed_mof API来调用, 以下为在srv6协议栈中提取出Srv6_2_Protocol协议中的segmentlist字段的案例。
```
import org.onosproject.net.packet.mof.*;
import org.onosproject.net.flow.instructions.protocol.*;
import org.onlab.packet.*;
import org.onosproject.net.flow.criteria.*;

@Override
public void process(PacketContext context) {
    MOFFlow mof_flow = context.inPacket().parsed_mof();
    // 获取第四层数据            
    MOFL4Layer ml4 = mof_flow.getL4Layer(); 
    // 判断数据包是否含有该协议
    if(ml4.isSrv6_2_Protocol()){ 
        // 取出协议
        Srv6_2_Protocol srv6_2 = ml4.getSrv6_2_Protocol(); 
        // 取出字段
        byte[] srv6_segmentlist1 = srv6_2.srv6_segmentlist1.value().toBytes(); 
    }
}
```

	
在多协议中字段有两种类型,一种以byte数组的形式存在, 一种以long字段的形式存在, 对于1,2,4字节的属性通过long类型来表示, 其余通过byte数组表示.以下为在srv6协议栈中提取出Srv6_2_Protocol协议中的长度字段的案例。
```
@Override
public void process(PacketContext context) {
    MOFFlow mof_flow = context.inPacket().parsed_mof();
    // 获取第四层数据      
    MOFL4Layer ml4 = mof_flow.getL4Layer(); 
    // 判断数据包是否含有该协议
    if(ml4.isSrv6_2_Protocol()){ 
        // 取出协议
        Srv6_2_Protocol srv6_2 = ml4.getSrv6_2_Protocol(); 
        // 取出字段
        long seg_n = srv6_2.srv6_hdr_ext_len.value();
    }
}
```

需要说明的是,这些字段的名称与配置文件中用户配置的名称是一致的,在上述例子中, 对应的yaml配置文件为:
```
srv6_2 :
  srv6_type : 
    size : 8
  srv6_hdr_ext_len : //取出的基本类型(1,2,4Byte)字段
    size : 8
  srv6_routing_Type : 
    size : 8
  srv6_segments_left : 
    size : 8 
  srv6_last_enty : 
    size : 8
  srv6_flags : 
    size : 8
  srv6_tag :
    size : 16
  srv6_segmentlist1 : //取出的非基本类型字段
    size : 128
  srv6_segmentlist2 : 
    size : 128
    
  Type : 
    srv6_TYPE_tcp : '0x06'
    srv6_TYPE_udp : '0x11'
```

##### 组装流表(匹配域)
当取出了数据包的字段后,接下来就是用户自定义的一系列处理流程,并开始组装想要下发的流表, 这里演示以入端口, MAC层目的地址及类型和3.6.1.1讲述的srv6_segmentlist1和seg_n两个字段为匹配域举例:
```
Ethernet inPkt = context.inPacket().parsed();

TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
MOFFlow mof_flow = context.inPacket().parsed_mof();
MOFL4Layer ml4 = mof_flow.getL4Layer();
if(ml4.isSrv6_2_Protocol()){
    // 取出字段
    Srv6_2_Protocol srv6_2 = ml4.getSrv6_2_Protocol();
    byte[] srv6_segmentlist1 = srv6_2.srv6_segmentlist1.value().toBytes();
    long seg_n = srv6_2.srv6_hdr_ext_len.value();

    // 开始组装流表
    selector.selectSrv6_Hdr_Ext_Len(seg_n)
            .selectSrv6_Segmentlist1(Srv6_Segmentlist1.valueOf(srv6_segmentlist1));
}
Mac_Dst mac_dst = Mac_Dst.valueOf(inPkt.getDestinationMACAddress());
byte[] byteArray = new byte[Mac_Dst.LEN];
Arrays.fill(byteArray, (byte)-1);
Mac_Dst mac_dst_mask = Mac_Dst.valueOf(byteArray);
// 继续组装流表
selector.selectInport(context.inPacket().receivedFrom().port().toLong())
        .selectMac_Dst(mac_dst, mac_dst_mask)
        .selectDl_Type(inPkt.getEtherType());
```
所有的匹配都以select开头+匹配内容, 每种匹配类型都有两个匹配函数, 一种是带掩码的匹配函数, 一种是不带掩码的匹配函数。
上述例子中匹配MAC目的地址时选择了带掩码的匹配函数, 其余皆为不带掩码的匹配函数。
##### 组装流表(动作域)
接下来则是定义对于这条流需要发生的动作, 会将所有支持的动作一起进行展示(详细用法在OVS描述中已经阐述,这里不在说明)。
注: 展示的例子仅为演示用法, 不考虑逻辑的合理性。
```
Dl_Protocol dl_protcol = new Dl_Protocol(new Dl_TypeCriterion(0x800));
TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                    .treatOutput(portNumber)
                                    .transition(1) // goto Table action
                                    .treatDeleteProtocol(Protocol.IPV4_E)
                                    .treatSegRougting()
                                    .treatMoveProtocol(Protocol.IPV4_E, Protocol.IPV4_I)
                                    .treatAddProtocol(Protocol.DL, dl_protcol)
                                    .treatModField(Protocol.DL, dl_protcol)
                                    .build();
```
关于Protocol类名称的定义 - 取决于yaml文件
```
dl : //名称 + protocol后缀
   dl_type :
     size : 16 
   
   Type :  
     dl_TYPE_ipv4_e : '0x0800'
     dl_TYPE_ipv6_e : '0x86DD'

   Hash :
    - dl_type
```
关于Protocol的类型定义 - 查看Protocol接口里, 取决于yaml文件
```
public interface Protocol {
    final int UNKNOW = 0;
    final int MAC = 1 << 0;
    final int VLAN1 = 1 << 1;
    final int VLAN2 = 1 << 2;
    final int DL = 1 << 3;
    final int IPV4_E = 1 << 4;
    final int IPV6_E = 1 << 5;
    final int TCP = 1 << 6;
    final int UDP = 1 << 7;
    final int SRV6_1 = 1 << 8;
    final int SRV6_2 = 1 << 9;
    final int SRV6_3 = 1 << 10;
    final int IPV6_I = 1 << 11;
    final int IPV4_I = 1 << 12;
    
    .....
}
```
##### 组装流表(创建发送对象)
当匹配域和动作域编写好后, 则可以进行发送操作。
1)添加流表
```
ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
        .withSelector(selector.build())
        .withTreatment(treatment)
        .withPriority(flowPriority)
        .withFlag(ForwardingObjective.Flag.SPECIFIC)
        .withTableId(0)
        .fromApp(appId)
        .makeTemporary(flowTimeout)
        .add();

flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                             forwardingObjective);
```
2)删除流表 - 五个属性唯一确定一条流表, 分别是<br>
a. 设备ID, 由context.inPacket().receivedFrom().deviceId()接口获取<br>
b. 表ID, [0-254]表范围<br>
c. 匹配域, 想要删除流表对应的匹配域<br>
d. 优先级, 删除流表对应的流表优先级<br>
e. 应用ID, 也就是appId,格式一般为org.onosproject.XXX, 每个ONOS应用都有一个唯一的appId,<br>下述例子的appId为org.onosproject.fwd<br>
```
ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
        .withSelector(selector.build())
        .withTreatment(treatment) // 必须指定, 可以创建一个空的动作域
        .withPriority(flowPriority)
        .withFlag(ForwardingObjective.Flag.SPECIFIC)
        .withTableId(0)
        .fromApp(appId)
        .remove();

flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                             forwardingObjective);
```

#### Restful API介绍
RESTful API 是一种允许软件应用通过 HTTP 协议与ONOS进行通信的接口。ONOS接收这类请求并转换成相应的控制命令传输给交换机。
##### 添加流表接口
消息头(POST)
```
http://{{IP:Port}}/onos/v1/flowobjectives/{{deviceId}}/forward?appId=org.onosproject.openflow
```

授权信息为ONOS的账号和密码, 默认为onos和rocks。

消息体
对于匹配域criteria, 每种类型皆可指定掩码, 以下例子中部分字段使用掩码展示。
```
{
    "flag": "SPECIFIC",
    "priority": 40000, //流表的优先级,, 优先级越高, 越先被匹配,不指定默认为最低优先级[0, 65535]
    "timeout": 0, //超时时间(s),如果isPermanent为true,则这个字段无效
    "isPermanent": true,//
    "deviceId": "{{deviceId}}", //需要指定设备id
    "tableId": 8, //tableId[0, 254]
    "operation": "ADD", //添加流表
    "selector": { //匹配域
        "criteria": [
            {
                "type": "MAC_DST",
                "mac_dst": "C5E0408DA6BA" //Mac目的地址
            },
            {
                "type": "IPV6_SRC_E",
                "ipv6_src_e": "0x1F5695ABF643418C803E4D5E20515A19/0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" //ipv6
            },
            {
                "type": "IP_DADDR_E",
                "ip_daddr_e": "0x0A000001/0xFFFFFF00" //ipv4
            },
            {
                "type": "SRV6_SEGMENTLIST1",
                "srv6_segmentlist1": "0x19135C6007F7448A041554FF67263E8C/0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            },
            {
                "type": "DL_TYPE",
                "dl_type": "0x888" 
            }
        ]
    },
    "treatment": { //动作
        "instructions": [
            {
                "type": "ADD_PROTOCOL", //添加协议动作, 指定需要添加的协议和值
                "protocol": "MAC_PROTOCOL",
                "criteria":[
                    {
                        "type": "MAC_DST",
                        "mac_dst": "C5E0408DA6BA" 
                    },
                    {
                        "type": "MAC_SRC",
                        "mac_src": "C5E0408DA6AB" 
                    }
                ]
            },
            {
                "type": "ADD_PROTOCOL", //添加协议动作, 制定需要添加的协议和值
                "protocol": "DL_PROTOCOL",
                "criteria":[
                    {
                        "type": "DL_TYPE",
                        "dl_type": "0x800" 
                    }
                ]
            },
            {
                "type": "DELETE_PROTOCOL", //删除协议动作, 制定需要删除的协议
                "protocol": "MAC_PROTOCOL"
            },
            {
                "type": "MOVE_PROTOCOL", //移动协议动作, 制定源和目的
                "src_protocol": "DL_PROTOCOL",
                "dst_protocol": "MAC_PROTOCOL"
            },
            {
                "type": "MOD_FIELD", //重制协议动作, 指定需要重置的协议和值
                "protocol": "MAC_PROTOCOL",
                "criteria":[
                    {
                        "type": "MAC_DST",
                        "mac_dst": "C5E0408DA6CD" 
                    },
                    {
                        "type": "MAC_SRC",
                        "mac_src": "C5E0408DA6DC" 
                    }
                ]
            },
            {
                "type": "SEG_ROUGTING"  //srv6的动作
            },
            {
                "type": "TABLE", // goto table动作
                "tableId": 2
            },
            {
                "type": "OUTPUT", // 指定对应匹配的包的出端口
                "port": 10
            }
        ]
    }
}
```
##### 删除流表接口
消息头(POST)
```
http://{{IP:Port}}/onos/v1/flowobjectives/{{deviceId}}/forward?appId=org.onosproject.openflow
```

授权信息为ONOS的账号和密码, 默认为onos和rocks

消息体
对于匹配域criteria, 每种类型皆可指定掩码, 以下例子中部分字段使用掩码展示。
```
{
    "flag": "SPECIFIC",
    "priority": 40000, //模糊删除不需要指定优先级
    "deviceId": "{{deviceId}}", //需要指定设备id
    "tableId": 8, // 指定需要删除的tableId[0, 254], 如果为255则表示全表删除
    "operation": "REMOVE", //删除流表
    "selector": { //匹配域
        "criteria": [
            {
                "type": "MAC_DST",
                "mac_dst": "C5E0408DA6BA" //Mac目的地址
            },
            {
                "type": "IPV6_SRC_E",
                "ipv6_src_e": "0x1F5695ABF643418C803E4D5E20515A19/0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" //ipv6
            },
            {
                "type": "IP_DADDR_E",
                "ip_daddr_e": "0x0A000001/0xFFFFFF00" //ipv4
            },
            {
                "type": "SRV6_SEGMENTLIST1",
                "srv6_segmentlist1": "0x19135C6007F7448A041554FF67263E8C/0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            },
            {
                "type": "DL_TYPE",
                "dl_type": "0x888"
            }
        ]
    },
    "treatment": { //动作
        "instructions": []
    }
}
```
### 图形操作界面及命令行
#### 图形操作界面
默认的ONOS账号和密码为onos和rocks
```
http://{{IP:8181}}/onos/ui/#/topo2 
```

#### 命令行
进入当前的ONOS目录
```
cd /path/to/onos
```
启动onos终端
```
tools/test/bin/onos localhost
```

查看流表
```
flows
```


#### 自定义流表显示功能
默认的显示模式为16进制的字段/掩码, 上述3.6.2.1的流表格式为
![image](https://github.com/WJSGDBZ/MOF-ONOS/assets/50448108/03e8dd19-0e11-4712-aa70-85ef45d108ea)
我们暴露了一个接口以帮助想自定义显示的格式的用户, 比如屏蔽某些字段的掩码位.具体在
onos/core/api/src/main/java/org/onosproject/net/flow/criteria/parser/CriterionParser.java 目录下
我们还提供了一些hepler函数来帮助用户简化开发具体可以参考代码中的Parser Helper Function 部分。
```
package org.onosproject.net.flow.criteria.parser;

import org.onosproject.net.flow.criteria.Criterion.Type;;

public final class CriterionParser {
   .........
   
    /*****************************************************************************
     * Parser Helper Function
     *****************************************************************************/

    /**
     * Parser hepler function
     * @input  byte[] data
     * @return Hex format String of data
     */
    public static String encodeHexStringHelper(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Parser hepler function
     * @input  byte[] data : ipv6 Address
     *         byte[] mask : ipv6 Mask Address
     * @return customer-friendly IPV6 Fromat String
     */
    public static String encodeIPV6StringHelper(byte[] data, byte[] mask) {
        String[] result = new String[2];

        // Convert IP bytes to IPv6 string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            sb.append(String.format("%02X%02X", data[i], data[i + 1]));
            if (i < 14) {
                sb.append(":");
            }
        }
        result[0] = sb.toString();
    
        // Convert mask bytes to prefix length
        int prefixLength = 0;
        for (byte b : mask) {
            for (int i = 7; i >= 0; i--) {
                if ((b & (1 << i)) != 0) {
                    prefixLength++;
                } else {
                    break;
                }
            }
        }
        result[1] = "/" + prefixLength;
    
        return result[0] + result[1];
    }

    /**
     * Parser hepler function
     * @input  int data : ipv4 Address
     *         int mask : ipv4 Mask Address
     * @return customer-friendly IPV4 Fromat String
     */
    public static String encodeIPV4StringHelper(long data, long mask) {
        String[] result = new String[2];
        result[0] = String.format("%d.%d.%d.%d", (data >> 24) & 0xFF, (data >> 16) & 0xFF, (data >> 8) & 0xFF, data & 0xFF);

        int bits = 0;
        for (int i = 31; i >= 0; i--) {
            if ((mask & (1L << i)) != 0) {
                bits++;
            } else {
                break;
            }
        }
        result[1] = "/" + bits;

        return result[0] + result[1];
    }

    /**
     * Parser hepler function
     * @input  byte[] data : MAC Address
     *         byte[] mask : MAC Mask Address
     * @return customer-friendly MAC Fromat String
     */
    public static String encodeMACStringHelper(byte[] data, byte[] mask) {
        String address = String.format("%02X:%02X:%02X:%02X:%02X:%02X", 
                            data[0], data[1], data[2], data[3], data[4], data[5]);

        int bits = 0;
        for (byte b : mask) {
            for (int i = 7; i >= 0; i--) {
                if ((b & (1 << i)) != 0) {
                    bits++;
                } else {
                    break;
                }
            }
        }

        return address + "/" + bits;
    }
}
```


这里我们将MAC协议字段显示进行优化举例
```
   //parser 1, 2, 4 bytes 
    public static String BasicParser(long data, long mask, Type type) {
        switch(type){
        case DL_TYPE:
            return PREFIX + Long.toHexString(data);
        .....
        }
        
    // others 
    public static String ComplexParser(byte[] data, byte[] mask, Type type) {
        switch(type){
        case MAC_DST:
            return encodeMACStringHelper(data, mask);
        case MAC_SRC:
            return encodeMACStringHelper(data, mask);
        case IPV6_SRC_E:
        case IPV6_DST_E:
        case SRV6_SEGMENTLIST3:
        case SRV6_SEGMENTLIST2:
        case SRV6_SEGMENTLIST1:
        case IPV6_SRC_I:
        case IPV6_DST_I:
        default:
            return PREFIX + encodeHexStringHelper(data) + "/" + PREFIX + encodeHexStringHelper(mask);
        }
    }
```
此时的流表显示如图, 注意查看MAC_DST和DL_TYPE字段。
![image](https://github.com/WJSGDBZ/MOF-ONOS/assets/50448108/7b1d5365-3f47-4fc7-b3b3-fe8faf4fa733)


#### 自定义数据包解析逻辑
这个功能是对于PacketIn消息的补充, 对于定长字段, ONOS可以直接按照每个字段长度进行读取。但是对于变长协议, 字段的长度取决于协议中的某个字段, 这种类型的协议无法通过通用协议处理流程, 因此需要单独暴露出来让用户自定义流程, 接下来会以Srv6协议举例。
首先需要在main.yaml文件中指出特殊协议:
```
Layer2: 
  - mac
Layer2_5:
  - vlan1
  - vlan2
Layer2_e:
  - dl
Layer3 : 
  - ipv4_e
  - ipv6_e
Layer4 :
  - tcp
  - udp
  - srv6
Layer5 :
  - ipv6_i
  - ipv4_i
Layer6 :
  - NULL

Specific :
    - srv6 // 指出特殊协议
```
然后代码生成器会捕捉到这个特殊协议, 并生成对应的处理框架,
具体在
onos/core/api/src/main/java/org/onosproject/net/flow/instructions/protocol/Specific_Protocol.java 文件里
```
public class Specific_Protocol {
......
    public void parse_specific_protocolL4(int type, ByteBuf bb, MOFL4Layer l4){
        switch (type) {
            case 0x12:
                throw new UnsupportedOperationException("L4Layer type 0x12 is undefine");
            default:
                break;
        }
    }
......
}
```
这时用户需要针对Srv6协议进行自定义读取
```
public void parse_specific_protocolL4(int type, ByteBuf bb, MOFL4Layer l4){
    switch (type) {
        case 0x12:
            int start = bb.readerIndex();
            bb.skipBytes(1);
            int hdr_ext_len = bb.readByte();
            bb.readerIndex(start);

            switch (hdr_ext_len) {
                case 1: l4.setSrv6_1_Protocol(Srv6_1_Protocol.read(bb));
                    break;
                case 2: l4.setSrv6_2_Protocol(Srv6_2_Protocol.read(bb));
                    break;
                case 3: l4.setSrv6_3_Protocol(Srv6_3_Protocol.read(bb));
                    break;
                default:
                    throw new UnsupportedOperationException("L4Layer type is unsupported");
            }
            break;
        default:
            break;
    }
}
```
需要注意的是Srv6对应的Srv6_1_Protocol, Srv6_2_Protocol, Srv6_3_Protocol协议类为编译器对Srv6的优化处理, 实际情况下用户需要根据字段自定义额外的协议类型(yaml文件定义的协议会自动生成)。
