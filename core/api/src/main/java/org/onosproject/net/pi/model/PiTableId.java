/*
 * Copyright 2017-present Open Networking Foundation
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

package org.onosproject.net.pi.model;

import com.google.common.annotations.Beta;
import org.onlab.util.Identifier;
import org.onosproject.net.flow.TableId;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Identifier of a table in a protocol-independent pipeline, unique within the scope of a pipeline model.
 */
@Beta
public final class PiTableId extends Identifier<String> implements TableId {

    private PiTableId(String name) {
        super(name);
    }

    /**
     * Returns an identifier for the given table name.
     *
     * @param name table name
     * @return table ID
     */
    public static PiTableId of(String name) {
        checkNotNull(name);
        checkArgument(!name.isEmpty(), "Name can't be empty");
        return new PiTableId(name);
    }

    @Override
    public Type type() {
        return Type.PIPELINE_INDEPENDENT;
    }

    @Override
    public int compareTo(TableId other) {
        if (this.type() != other.type()) {
            return this.type().compareTo(other.type());
        } else {
            PiTableId piTableId = (PiTableId) other;
            checkNotNull(this.identifier, "PiTableId identifier should not be null");
            checkNotNull(piTableId.identifier, "PiTableId identifier should not be null");
            return this.identifier.compareTo(piTableId.identifier);
        }
    }
    
    @Override
    public int getValue(){
        return 0;
    }
}
