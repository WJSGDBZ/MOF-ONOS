package org.onosproject.net.flow.instructions.protocol;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
import org.onosproject.net.flow.criteria.Criterion;

import org.onosproject.net.flow.criteria.Dl_TypeCriterion;

public class Dl_Protocol implements Protocol {
    Dl_TypeCriterion dl_type;

    public Dl_Protocol(Dl_TypeCriterion dl_type){
        this.dl_type = dl_type;
    }

    @Override
    public void write(ByteBuf bb){
        dl_type.write(bb);

        bb.writeZero(54);
    }
  
    @Override
    public void writeMask(ByteBuf bb){
        dl_type.writeMask(bb);

        bb.writeZero(54);
    }
  
    public static Dl_Protocol read(ByteBuf bb){
        Dl_TypeCriterion dl_type = new Dl_TypeCriterion.Builder()
                                                .setValid(true)
                                                .readData(bb)
                                                .build();
        
        bb.skipBytes(54);
        return new Dl_Protocol(dl_type);
    }

    public static Dl_Protocol readWithMask(ByteBuf bb){
        Dl_TypeCriterion.Builder b1 = new Dl_TypeCriterion.Builder();
        b1.readMask(bb);
        bb.skipBytes(54);

        b1.readData(bb);   
        bb.skipBytes(54);
        return new Dl_Protocol(b1.build());
    }

    @Override
    public String toString() {
        return "Dl_Protocol{ " + dl_type + " }";
    }

    @Override
    public int hashCode() {
        return Objects.hash(dl_type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Dl_Protocol) {
            Dl_Protocol that = (Dl_Protocol) obj;
            return Objects.equals(dl_type, that.dl_type);
        }
        return false;
    }

}
