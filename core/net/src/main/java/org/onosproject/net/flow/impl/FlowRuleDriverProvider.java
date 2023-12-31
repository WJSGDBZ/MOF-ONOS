/*
 * Copyright 2016-present Open Networking Foundation
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

package org.onosproject.net.flow.impl;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.LinkedListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.behaviour.TableStatisticsDiscovery;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.CompletedBatchOperation;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleProgrammable;
import org.onosproject.net.flow.FlowRuleProvider;
import org.onosproject.net.flow.FlowRuleProviderService;
import org.onosproject.net.flow.TableStatisticsEntry;
import org.onosproject.net.flow.oldbatch.FlowRuleBatchEntry;
import org.onosproject.net.flow.oldbatch.FlowRuleBatchOperation;
import org.onosproject.net.provider.AbstractProvider;
import org.onosproject.net.provider.ProviderId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static com.google.common.collect.ImmutableSet.copyOf;
import static com.google.common.collect.Lists.newArrayList;
import static java.util.concurrent.Executors.newSingleThreadScheduledExecutor;
import static org.onlab.util.Tools.groupedThreads;
import static org.onosproject.net.device.DeviceEvent.Type.DEVICE_ADDED;
import static org.onosproject.net.device.DeviceEvent.Type.DEVICE_AVAILABILITY_CHANGED;
import static org.onosproject.net.flow.oldbatch.FlowRuleBatchEntry.FlowRuleOperation.ADD;
import static org.onosproject.net.flow.oldbatch.FlowRuleBatchEntry.FlowRuleOperation.MODIFY;
import static org.onosproject.net.flow.oldbatch.FlowRuleBatchEntry.FlowRuleOperation.REMOVE;

/**
 * Driver-based flow rule provider.
 */
class FlowRuleDriverProvider extends AbstractProvider implements FlowRuleProvider {

    private final Logger log = LoggerFactory.getLogger(FlowRuleDriverProvider.class);

    // Perhaps to be extracted for better reuse as we deal with other.
    public static final String SCHEME = "default";
    public static final String PROVIDER_NAME = "org.onosproject.provider";

    FlowRuleProviderService providerService;
    private DeviceService deviceService;
    private MastershipService mastershipService;

    private InternalDeviceListener deviceListener = new InternalDeviceListener();
    private ScheduledExecutorService executor
        = newSingleThreadScheduledExecutor(groupedThreads("FlowRuleDriverProvider", "%d", log));
    private ScheduledFuture<?> poller = null;

    /**
     * Creates a new fallback flow rule provider.
     */
    FlowRuleDriverProvider() {
        super(new ProviderId(SCHEME, PROVIDER_NAME));
    }

    /**
     * Initializes the provider with necessary supporting services.
     *
     * @param providerService   flow rule provider service
     * @param deviceService     device service
     * @param mastershipService mastership service
     * @param pollFrequency     flow entry poll frequency
     */
    void init(FlowRuleProviderService providerService,
              DeviceService deviceService, MastershipService mastershipService,
              int pollFrequency) {
        this.providerService = providerService;
        this.deviceService = deviceService;
        this.mastershipService = mastershipService;

        deviceService.addListener(deviceListener);

        if (poller != null && !poller.isCancelled()) {
            poller.cancel(false);
        }

        poller = executor.scheduleAtFixedRate(this::pollFlowEntries, pollFrequency,
                                              pollFrequency, TimeUnit.SECONDS);
    }

    void terminate() {
        deviceService.removeListener(deviceListener);
        deviceService = null;
        providerService = null;
        mastershipService = null;
        poller.cancel(true);
        executor.shutdown();
    }

    @Override
    public void applyFlowRule(FlowRule... flowRules) {
        rulesByDevice(flowRules).asMap().forEach(this::applyFlowRules);
    }

    @Override
    public void removeFlowRule(FlowRule... flowRules) {
        rulesByDevice(flowRules).asMap().forEach(this::removeFlowRules);
    }

    @Override
    public void executeBatch(FlowRuleBatchOperation batch) {
        log.info("FlowRuleDriveProvider execute Batch!!");
        ImmutableList.Builder<FlowRule> toAdd = ImmutableList.builder();
        ImmutableList.Builder<FlowRule> toRemove = ImmutableList.builder();
        for (FlowRuleBatchEntry fbe : batch.getOperations()) {
            if (fbe.operator() == ADD || fbe.operator() == MODIFY) {
                toAdd.add(fbe.target());
            } else if (fbe.operator() == REMOVE) {
                toRemove.add(fbe.target());
            }
        }

        ImmutableList<FlowRule> rulesToAdd = toAdd.build();
        ImmutableList<FlowRule> rulesToRemove = toRemove.build();

        Collection<FlowRule> added = ImmutableList.of();
        if (!rulesToAdd.isEmpty()) {
            added = applyFlowRules(batch.deviceId(), rulesToAdd);
        }
        Collection<FlowRule> removed = ImmutableList.of();
        if (!rulesToRemove.isEmpty()) {
            removed = removeFlowRules(batch.deviceId(), rulesToRemove);
        }

        Set<FlowRule> failedRules = Sets.union(Sets.difference(copyOf(rulesToAdd), copyOf(added)),
                                               Sets.difference(copyOf(rulesToRemove), copyOf(removed)));
        CompletedBatchOperation status =
                new CompletedBatchOperation(failedRules.isEmpty(), failedRules, batch.deviceId());
        providerService.batchOperationCompleted(batch.id(), status);
    }

    private Multimap<DeviceId, FlowRule> rulesByDevice(FlowRule[] flowRules) {
        // Sort the flow rules by device id
        Multimap<DeviceId, FlowRule> rulesByDevice = LinkedListMultimap.create();
        for (FlowRule rule : flowRules) {
            rulesByDevice.put(rule.deviceId(), rule);
        }
        return rulesByDevice;
    }

    private Collection<FlowRule> applyFlowRules(DeviceId deviceId, Collection<FlowRule> flowRules) {
        FlowRuleProgrammable programmer = getFlowRuleProgrammable(deviceId);
        log.info("truly programmer is {}", programmer.getClass().toString());
        return programmer != null ? programmer.applyFlowRules(flowRules) : ImmutableList.of();
    }

    private Collection<FlowRule> removeFlowRules(DeviceId deviceId, Collection<FlowRule> flowRules) {
        FlowRuleProgrammable programmer = getFlowRuleProgrammable(deviceId);
        return programmer != null ? programmer.removeFlowRules(flowRules) : ImmutableList.of();
    }

    private FlowRuleProgrammable getFlowRuleProgrammable(DeviceId deviceId) {
        Device device = deviceService.getDevice(deviceId);
        if (device.is(FlowRuleProgrammable.class)) {
            return device.as(FlowRuleProgrammable.class);
        } else {
            log.debug("Device {} is not flow rule programmable", deviceId);
            return null;
        }
    }

    private void pollDeviceFlowEntries(Device device) {
        try {
            providerService.pushFlowMetrics(device.id(), device.as(FlowRuleProgrammable.class).getFlowEntries());
        } catch (Exception e) {
            log.warn("Exception thrown while polling {}", device.id(), e);
        }
    }

    private void pollTableStatistics(Device device) {
        try {
            List<TableStatisticsEntry> tableStatsList = newArrayList(device.as(TableStatisticsDiscovery.class)
                    .getTableStatistics());
            providerService.pushTableStatistics(device.id(), tableStatsList);
        } catch (Exception e) {
            log.warn("Exception thrown while polling table statistics for {}", device.id(), e);
        }
    }

    private void pollFlowEntries() {
        try {
            deviceService.getAvailableDevices().forEach(device -> {
                if (mastershipService.isLocalMaster(device.id()) && device.is(FlowRuleProgrammable.class)) {
                    pollDeviceFlowEntries(device);
                }
                if (mastershipService.isLocalMaster(device.id()) && device.is(TableStatisticsDiscovery.class)) {
                    pollTableStatistics(device);
                }
            });
        } catch (Exception e) {
            log.warn("Exception thrown while polling flows", e);
        }
    }

    // potentially positive device event
    private static final Set<DeviceEvent.Type> POSITIVE_DEVICE_EVENT =
            Sets.immutableEnumSet(DEVICE_ADDED,
                                  DEVICE_AVAILABILITY_CHANGED);

    private class InternalDeviceListener implements DeviceListener {

        @Override
        public void event(DeviceEvent event) {
            executor.execute(() -> handleEvent(event));
        }

        @Override
        public boolean isRelevant(DeviceEvent event) {
            Device device = event.subject();
            return POSITIVE_DEVICE_EVENT.contains(event.type()) &&
                   device.is(FlowRuleProgrammable.class);
        }

        private void handleEvent(DeviceEvent event) {
            Device device = event.subject();
            boolean isRelevant = mastershipService.isLocalMaster(device.id()) &&
                    deviceService.isAvailable(device.id());

            if (isRelevant) {
                pollDeviceFlowEntries(device);
            }
        }
    }

}
