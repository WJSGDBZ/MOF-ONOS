/*
 * Copyright 2015-present Open Networking Foundation
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
package org.onosproject.net.flow.criteria;

import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.criteria.Criterion;

import java.util.Objects;
import io.netty.buffer.ByteBuf;
/**
 * Implementation of input port criterion.
 */
public final class TestCriterion implements Criterion {
    private final int value;
    private final Type type;

    /**
     * Constructor.
     *
     * @param port the input value number to match
     * @param type the match type
     */
    TestCriterion(int value, Type type) {
        this.value = value;
        this.type = type;
    }

    @Override
    public void write(ByteBuf bb){}
    @Override
    public void writeMask(ByteBuf bb){
        
    }
    @Override
    public Type type() {
        return this.type;
    }

    /**
     * Gets the input value number to match.
     *
     * @return the input value number to match
     */
    public int value() {
        return this.value;
    }

    @Override
    public String toString() {
        return type().toString() + SEPARATOR + value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(type().ordinal(), value);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof TestCriterion) {
            TestCriterion that = (TestCriterion) obj;
            return Objects.equals(value, that.value) &&
                    Objects.equals(this.type(), that.type());
        }
        return false;
    }
}
