package org.onosproject.provider.of.flow.mof.impl;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.ver10.*;
import org.projectfloodlight.openflow.protocol.action.*;
import org.projectfloodlight.openflow.protocol.actionid.*;
import org.projectfloodlight.openflow.protocol.bsntlv.*;
import org.projectfloodlight.openflow.protocol.errormsg.*;
import org.projectfloodlight.openflow.protocol.meterband.*;
import org.projectfloodlight.openflow.protocol.instruction.*;
import org.projectfloodlight.openflow.protocol.instructionid.*;
import org.projectfloodlight.openflow.protocol.match.*;
import org.projectfloodlight.openflow.protocol.stat.*;
import org.projectfloodlight.openflow.protocol.oxm.*;
import org.projectfloodlight.openflow.protocol.oxs.*;
import org.projectfloodlight.openflow.protocol.queueprop.*;
import org.projectfloodlight.openflow.types.*;
import org.projectfloodlight.openflow.util.*;
import org.projectfloodlight.openflow.exceptions.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Set;
import com.google.common.collect.ImmutableSet;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import com.google.common.collect.ImmutableList;
import io.netty.buffer.ByteBuf;
import com.google.common.hash.PrimitiveSink;
import com.google.common.hash.Funnel;

import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.provider.of.flow.mof.api.MofFlowMod;

public class MofFlowDelImpl implements MofFlowMod{
    private static final Logger log = LoggerFactory.getLogger(MofFlowDelImpl.class);
    // version: 1.0
    final static byte WIRE_VERSION = 1;
    final static int MINIMUM_LENGTH = 72;
    // maximum OF message length: 16 bit, unsigned
    final static int MAXIMUM_LENGTH = 0xFFFF;

        private final static long DEFAULT_XID = 0x0L;
        //private final static Match DEFAULT_MATCH = OFFactoryVer10.MATCH_WILDCARD_ALL;
        private final static U64 DEFAULT_COOKIE = U64.ZERO;
        private final static int DEFAULT_IDLE_TIMEOUT = 0x0;
        private final static int DEFAULT_HARD_TIMEOUT = 0x0;
        private final static int DEFAULT_PRIORITY = 0x0;
        private final static OFBufferId DEFAULT_BUFFER_ID = OFBufferId.NO_BUFFER;
        private final static OFPort DEFAULT_OUT_PORT = OFPort.ANY;
        private final static Set<OFFlowModFlags> DEFAULT_FLAGS = ImmutableSet.<OFFlowModFlags>of();
        private final static List<OFAction> DEFAULT_ACTIONS = ImmutableList.<OFAction>of();
        private final static TableId DEFAULT_TABLE_ID = TableId.of(0);
    // OF message fields
    private final long xid;
    private final TrafficSelector selector;
    private final Match match;
    private final U64 cookie;
    private final int idleTimeout;
    private final int hardTimeout;
    private final int priority;
    private final OFBufferId bufferId;
    private final OFPort outPort;
    private final Set<OFFlowModFlags> flags;
    private final TrafficTreatment treatment;
    private final List<OFAction> actions;
    private final TableId tableId;


    protected MofFlowDelImpl(TrafficSelector selector, TrafficTreatment treatment){
        this.xid = DEFAULT_XID & 0xFFFF_FFFFL;
        this.cookie = DEFAULT_COOKIE;
        // this.idleTimeout = U16.normalize(idleTimeout);
        // this.hardTimeout = U16.normalize(hardTimeout);
        //this.priority = U16.normalize(priority);
        this.idleTimeout = DEFAULT_IDLE_TIMEOUT & 0xFFFF;
        this.hardTimeout = DEFAULT_HARD_TIMEOUT & 0xFFFF;
        this.priority = DEFAULT_PRIORITY & 0xFFFF;
        this.bufferId = DEFAULT_BUFFER_ID;
        this.outPort = DEFAULT_OUT_PORT;
        this.flags = DEFAULT_FLAGS;
        this.treatment = treatment;
        this.selector = selector;
        this.tableId = DEFAULT_TABLE_ID;
        this.match = null;
        this.actions = null;
    }

    MofFlowDelImpl(long xid, TrafficSelector selector, U64 cookie, int idleTimeout, int hardTimeout, int priority, OFBufferId bufferId, OFPort outPort, Set<OFFlowModFlags> flags, TrafficTreatment treatment, TableId tableId) {
        if(selector == null) {
            throw new NullPointerException("MofFlowDelImpl: property selector cannot be null");
        }
        if(cookie == null) {
            throw new NullPointerException("MofFlowDelImpl: property cookie cannot be null");
        }
        if(bufferId == null) {
            throw new NullPointerException("MofFlowDelImpl: property bufferId cannot be null");
        }
        if(outPort == null) {
            throw new NullPointerException("MofFlowDelImpl: property outPort cannot be null");
        }
        if(flags == null) {
            throw new NullPointerException("MofFlowDelImpl: property flags cannot be null");
        }
        if(treatment == null) {
            throw new NullPointerException("MofFlowDelImpl: property treatment cannot be null");
        }
        if(tableId == null) {
            throw new NullPointerException("MofFlowDelImpl: property tableId cannot be null");
        }
        //this.xid = U32.normalize(xid);
        this.xid = xid & 0xFFFF_FFFFL;
        this.cookie = cookie;
        // this.idleTimeout = U16.normalize(idleTimeout);
        // this.hardTimeout = U16.normalize(hardTimeout);
        //this.priority = U16.normalize(priority);
        this.idleTimeout = idleTimeout & 0xFFFF;
        this.hardTimeout = hardTimeout & 0xFFFF;
        this.priority = priority & 0xFFFF;
        this.bufferId = bufferId;
        this.outPort = outPort;
        this.flags = flags;
        this.treatment = treatment;
        this.selector = selector;
        this.match = null;
        this.actions = null;
        this.tableId = tableId;
    }

    public void writeTo(ByteBuf bb){
        //log.info("MofFlowDelImpl ready to write!!!");
        WRITER.write(bb, this);
    }

    final static Writer WRITER = new Writer();
    static class Writer implements OFMessageWriter<MofFlowDelImpl> {
        @Override
        public void write(ByteBuf bb, MofFlowDelImpl message) {
        int startIndex = bb.writerIndex();
        // fixed value property version = 1
        bb.writeByte((byte) 0x1);
        // fixed value property type = ff
        bb.writeByte((byte) 0xff);
        // length is length of variable message, will be updated at the end
        int lengthIndex = bb.writerIndex();
        bb.writeShort(U16.t(0));

        bb.writeInt(U32.t(message.xid));

        //openflow
        //message.selector.writeTo(bb); 

        bb.writeLong(message.cookie.getValue());
        //tableId;
        message.tableId.writeByte(bb);
        //log.info("Mof delete flow on tableId" + message.tableId);
        // fixed value property command = 3
        bb.writeByte(0x03);
        bb.writeShort(U16.t(message.idleTimeout));
        bb.writeShort(U16.t(message.hardTimeout));
        bb.writeShort(0x0);
        bb.writeInt(message.bufferId.getInt());
        message.outPort.write2Bytes(bb);
        OFFlowModFlagsSerializerVer10.writeTo(bb, message.flags);
        
        //openflow
        //message.treatment.writeTo(bb);

        //mof
        message.selector.writeTo(bb); 

        //ChannelUtils.writeList(bb, message.treatment.allInstructions());
        //ChannelUtils.writeList(bb, Collections.emptyList());

        // update length field
        int length = bb.writerIndex() - startIndex;
        if (length > MAXIMUM_LENGTH) {
        throw new IllegalArgumentException("MofFlowDelImpl: message length (" + length + ") exceeds maximum (0xFFFF)");
        }
        bb.setShort(lengthIndex, length);
        log.info("MofFlowDelImpl write done!!!");

        }  
    }

    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }
    final static OFFlowAddVer10Funnel FUNNEL = new OFFlowAddVer10Funnel();
    static class OFFlowAddVer10Funnel implements Funnel<MofFlowDelImpl> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel(MofFlowDelImpl message, PrimitiveSink sink) {
        // fixed value property version = 1
        sink.putByte((byte) 0x1);
        // fixed value property type = ff
        sink.putByte((byte) 0xff);
        // FIXME: skip funnel of length
        sink.putLong(message.xid);

        //message.match.putTo(sink);

        message.cookie.putTo(sink);
        // fixed value property command = 0
        sink.putShort((short) 0x0);
        sink.putInt(message.idleTimeout);
        sink.putInt(message.hardTimeout);
        sink.putInt(message.priority);
        message.bufferId.putTo(sink);
        message.outPort.putTo(sink);
        OFFlowModFlagsSerializerVer10.putTo(message.flags, sink);

        //FunnelUtils.putList(message.actions, sink);
        }
    }

    @Override
    public OFVersion getVersion() {
    return OFVersion.OF_10;
    }

    @Override
    public OFType getType() {
    return OFType.FLOW_MOD;
    }


    @Override
    public long getXid() {
    return xid;
    }

    @Override
    public TrafficSelector getSelector() {
    return selector;
    }

    @Override
    public Match getMatch() {
    return match;
    }

    @Override
    public U64 getCookie() {
    return cookie;
    }

    @Override
    public OFFlowModCommand getCommand() {
    return OFFlowModCommand.ADD;
    }

    @Override
    public int getIdleTimeout() {
    return idleTimeout;
    }

    @Override
    public int getHardTimeout() {
    return hardTimeout;
    }

    @Override
    public int getPriority() {
    return priority;
    }

    @Override
    public OFBufferId getBufferId() {
    return bufferId;
    }

    @Override
    public OFPort getOutPort() {
    return outPort;
    }

    @Override
    public Set<OFFlowModFlags> getFlags() {
    return flags;
    }

    @Override
    public TrafficTreatment getTreatment() {
    return treatment;
    }


    public MofFlowMod.Builder createBuilder() {
        return null;
    }

    public static class Builder implements MofFlowMod.Builder {
    // OF message fields
    private boolean xidSet;
    private long xid;
    private boolean selectorSet;
    private TrafficSelector selector;
    private boolean matchSet;
    private Match match;
    private boolean cookieSet;
    private U64 cookie;
    private boolean idleTimeoutSet;
    private int idleTimeout;
    private boolean hardTimeoutSet;
    private int hardTimeout;
    private boolean prioritySet;
    private int priority;
    private boolean bufferIdSet;
    private OFBufferId bufferId;
    private boolean outPortSet;
    private OFPort outPort;
    private boolean flagsSet;
    private Set<OFFlowModFlags> flags;
    private boolean treatmentSet;
    private TrafficTreatment treatment;
    private boolean actionsSet;
    private TableId tableId;
    private boolean tableIdSet;

    List<OFAction> actions;

    @Override
    public OFVersion getVersion() {
        return OFVersion.OF_10;
    }

    @Override
    public OFType getType() {
        return OFType.FLOW_MOD;
    }

    @Override
    public long getXid() {
        return xid;
    }

    @Override
    public MofFlowMod.Builder setXid(long xid) {
        this.xid = xid;
        this.xidSet = true;
        return this;
    }

    @Override
    public TableId getTableId() {
        return tableId;
    }

    @Override
    public MofFlowMod.Builder setTableId(TableId tableId) {
        this.tableId = tableId;
        this.tableIdSet = true;
        return this;
    }

    @Override
    public TrafficSelector getSelector() {
        return selector;
    }

    @Override
    public MofFlowMod.Builder setSelector(TrafficSelector selector) {
        this.selector = selector;
        this.selectorSet = true;
        return this;
    }

    @Override
    public Match getMatch() {
        return match;
    }

    @Override
    public MofFlowMod.Builder setMatch(Match match) {
        this.match = match;
        this.matchSet = true;
        return this;
    }

    @Override
    public U64 getCookie() {
        return cookie;
    }

    @Override
    public MofFlowMod.Builder setCookie(U64 cookie) {
        this.cookie = cookie;
        this.cookieSet = true;
        return this;
    }
    @Override
    public OFFlowModCommand getCommand() {
        return OFFlowModCommand.ADD;
    }

    @Override
    public int getIdleTimeout() {
        return idleTimeout;
    }

    @Override
    public MofFlowMod.Builder setIdleTimeout(int idleTimeout) {
    this.idleTimeout = idleTimeout;
    this.idleTimeoutSet = true;
        return this;
    }
    @Override
    public int getHardTimeout() {
        return hardTimeout;
    }

    @Override
    public MofFlowMod.Builder setHardTimeout(int hardTimeout) {
    this.hardTimeout = hardTimeout;
    this.hardTimeoutSet = true;
        return this;
    }
    @Override
    public int getPriority() {
        return priority;
    }

    @Override
    public MofFlowMod.Builder setPriority(int priority) {
        this.priority = priority;
        this.prioritySet = true;
        return this;
    }

    @Override
    public OFBufferId getBufferId() {
       return bufferId;
    }

    @Override
    public MofFlowMod.Builder setBufferId(OFBufferId bufferId) {
        this.bufferId = bufferId;
        this.bufferIdSet = true;
        return this;
    }
    @Override
    public OFPort getOutPort() {
     return outPort;
    }

    @Override
    public MofFlowMod.Builder setOutPort(OFPort outPort) {
    this.outPort = outPort;
    this.outPortSet = true;
      return this;
    }
    @Override
    public Set<OFFlowModFlags> getFlags() {
       return flags;
    }

    @Override
    public MofFlowMod.Builder setFlags(Set<OFFlowModFlags> flags) {
    this.flags = flags;
    this.flagsSet = true;
       return this;
    }
    @Override
    public TrafficTreatment getTreatment() {
        return treatment;
    }

    public MofFlowMod.Builder setTreatment(TrafficTreatment treatment) {
        this.treatment = treatment;
        this.treatmentSet = true;
        return this;
    }

    @Override
    public List<OFAction> getActions() {
        return actions;
    }

    @Override
    public MofFlowMod.Builder setActions(List<OFAction> actions) {
        this.actions = actions;
        this.actionsSet = true;
        return this;
    }
    
    @Override
    public MofFlowMod build() {
        long xid = this.xidSet ? this.xid : DEFAULT_XID;
        TrafficSelector selector = this.selectorSet ? this.selector : null;
        if(selector == null)
        throw new NullPointerException("Property selector must not be null");
        U64 cookie = this.cookieSet ? this.cookie : DEFAULT_COOKIE;
        if(cookie == null)
        throw new NullPointerException("Property cookie must not be null");
        int idleTimeout = this.idleTimeoutSet ? this.idleTimeout : DEFAULT_IDLE_TIMEOUT;
        int hardTimeout = this.hardTimeoutSet ? this.hardTimeout : DEFAULT_HARD_TIMEOUT;
        int priority = this.prioritySet ? this.priority : DEFAULT_PRIORITY;
        OFBufferId bufferId = this.bufferIdSet ? this.bufferId : DEFAULT_BUFFER_ID;
        if(bufferId == null)
        throw new NullPointerException("Property bufferId must not be null");
        OFPort outPort = this.outPortSet ? this.outPort : DEFAULT_OUT_PORT;
        if(outPort == null)
        throw new NullPointerException("Property outPort must not be null");
        Set<OFFlowModFlags> flags = this.flagsSet ? this.flags : DEFAULT_FLAGS;
        if(flags == null)
        throw new NullPointerException("Property flags must not be null");
        TrafficTreatment treatment = this.treatmentSet ? this.treatment : null;
        if(treatment == null)
        throw new NullPointerException("Property treatment must not be null");
        if(tableId == null)
        throw new NullPointerException("Property tableId must not be null");

        return new MofFlowDelImpl(
        xid,
        selector,
        cookie,
        idleTimeout,
        hardTimeout,
        priority,
        bufferId,
        outPort,
        flags,
        treatment,
        tableId
        );
    }

    }
    
    @Override
    public int hashCodeIgnoreXid() {
        final int prime = 31;
        int result = 1;

        // ignore XID
        result = prime * result + ((selector == null) ? 0 : selector.hashCode());
        result = prime * result + ((cookie == null) ? 0 : cookie.hashCode());
        result = prime * result + idleTimeout;
        result = prime * result + hardTimeout;
        result = prime * result + priority;
        result = prime * result + ((bufferId == null) ? 0 : bufferId.hashCode());
        result = prime * result + ((outPort == null) ? 0 : outPort.hashCode());
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((treatment == null) ? 0 : treatment.hashCode());
        return result;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * (int) (xid ^ (xid >>> 32));
        result = prime * result + ((selector == null) ? 0 : selector.hashCode());
        result = prime * result + ((cookie == null) ? 0 : cookie.hashCode());
        result = prime * result + idleTimeout;
        result = prime * result + hardTimeout;
        result = prime * result + priority;
        result = prime * result + ((bufferId == null) ? 0 : bufferId.hashCode());
        result = prime * result + ((outPort == null) ? 0 : outPort.hashCode());
        result = prime * result + ((flags == null) ? 0 : flags.hashCode());
        result = prime * result + ((treatment == null) ? 0 : treatment.hashCode());
        return result;
    }

    @Override
    public boolean equalsIgnoreXid(Object obj) {
        if (this == obj)
        return true;
        if (obj == null)
        return false;
        if (getClass() != obj.getClass())
        return false;
        MofFlowDelImpl other = (MofFlowDelImpl) obj;

        // ignore XID
        if (selector == null) {
        if (other.selector != null)
        return false;
        } else if (!selector.equals(other.selector))
        return false;
        if (cookie == null) {
        if (other.cookie != null)
        return false;
        } else if (!cookie.equals(other.cookie))
        return false;
        if( idleTimeout != other.idleTimeout)
        return false;
        if( hardTimeout != other.hardTimeout)
        return false;
        if( priority != other.priority)
        return false;
        if (bufferId == null) {
        if (other.bufferId != null)
        return false;
        } else if (!bufferId.equals(other.bufferId))
        return false;
        if (outPort == null) {
        if (other.outPort != null)
        return false;
        } else if (!outPort.equals(other.outPort))
        return false;
        if (flags == null) {
        if (other.flags != null)
        return false;
        } else if (!flags.equals(other.flags))
        return false;
        if (treatment == null) {
        if (other.treatment != null)
        return false;
        } else if (!treatment.equals(other.treatment))
        return false;
        return true;
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("MofFlowDelImpl");
        b.append("xid=").append(xid);
        b.append(", ");
        b.append("selector=").append(selector);
        b.append(", ");
        b.append("cookie=").append(cookie);
        b.append(", ");
        b.append("idleTimeout=").append(idleTimeout);
        b.append(", ");
        b.append("hardTimeout=").append(hardTimeout);
        b.append(", ");
        b.append("priority=").append(priority);
        b.append(", ");
        b.append("bufferId=").append(bufferId);
        b.append(", ");
        b.append("outPort=").append(outPort);
        b.append(", ");
        b.append("flags=").append(flags);
        b.append(", ");
        b.append("treatment=").append(treatment);
        b.append(")");
        return b.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
        return true;
        if (obj == null)
        return false;
        if (getClass() != obj.getClass())
        return false;
        MofFlowDelImpl other = (MofFlowDelImpl) obj;

        if( xid != other.xid)
        return false;
        if (selector == null) {
        if (other.selector != null)
        return false;
        } else if (!selector.equals(other.selector))
        return false;
        if (cookie == null) {
        if (other.cookie != null)
        return false;
        } else if (!cookie.equals(other.cookie))
        return false;
        if( idleTimeout != other.idleTimeout)
        return false;
        if( hardTimeout != other.hardTimeout)
        return false;
        if( priority != other.priority)
        return false;
        if (bufferId == null) {
        if (other.bufferId != null)
        return false;
        } else if (!bufferId.equals(other.bufferId))
        return false;
        if (outPort == null) {
        if (other.outPort != null)
        return false;
        } else if (!outPort.equals(other.outPort))
        return false;
        if (flags == null) {
        if (other.flags != null)
        return false;
        } else if (!flags.equals(other.flags))
        return false;
        if (treatment == null) {
        if (other.treatment != null)
        return false;
        } else if (!treatment.equals(other.treatment))
        return false;
        return true;
    }
}