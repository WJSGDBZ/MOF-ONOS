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
package org.onosproject.net.flow.oldbatch;

import org.onosproject.net.flow.BatchOperationEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.oldbatch.FlowRuleBatchEntry.FlowRuleOperation;

@Deprecated
/**
 * @deprecated in Drake release - no longer a public API
 */
public class FlowRuleBatchEntry
        extends BatchOperationEntry<FlowRuleOperation, FlowRule> {

    private final Long id; // FIXME: consider using Optional<Long>

    public FlowRuleBatchEntry(FlowRuleOperation operator, FlowRule target) {
        super(operator, target);
        this.id = null;
    }

    public FlowRuleBatchEntry(FlowRuleOperation operator, FlowRule target, Long id) {
        super(operator, target);
        this.id = id;
    }

    public Long id() {
        return id;
    }

    public enum FlowRuleOperation {
        ADD,
        REMOVE,
        REMOVESPEFIC,
        MODIFY
    }

}
