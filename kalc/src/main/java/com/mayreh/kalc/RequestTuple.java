package com.mayreh.kalc;

import static com.mayreh.kalc.Utils.requireNoneOf;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.experimental.Accessors;

@Value
@Builder
@Accessors(fluent = true)
public class RequestTuple {
    @NonNull
    String userPrincipal;
    @NonNull
    String host;
    @NonNull
    AclOperation operation;
    @NonNull
    ResourceType resourceType;
    @NonNull
    String resourceName;

    public RequestTuple(
            String userPrincipal,
            String host,
            AclOperation operation,
            ResourceType resourceType,
            String resourceName) {
        this.userPrincipal = userPrincipal;
        this.host = host;
        this.operation = requireNoneOf(
                operation,
                AclOperation.UNKNOWN,
                AclOperation.ANY,
                AclOperation.ALL);
        this.resourceType = requireNoneOf(
                resourceType,
                ResourceType.UNKNOWN,
                ResourceType.ANY);
        this.resourceName = resourceName;
    }
}
