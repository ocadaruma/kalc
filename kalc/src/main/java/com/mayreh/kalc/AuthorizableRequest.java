package com.mayreh.kalc;

import static com.mayreh.kalc.Utils.requireNonWildcard;
import static com.mayreh.kalc.Utils.requireNoneOf;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import lombok.Builder;
import lombok.Value;
import lombok.experimental.Accessors;

/**
 * Represents the request that contains the principal and required authority.
 * So should not contain any wildcard or ALL.
 */
@Value
@Builder
@Accessors(fluent = true)
public class AuthorizableRequest {
    String userPrincipal;

    String host;

    AclOperation operation;

    ResourceType resourceType;

    String resourceName;

    public AuthorizableRequest(
            String userPrincipal,
            String host,
            AclOperation operation,
            ResourceType resourceType,
            String resourceName) {
        this.userPrincipal = requireNonWildcard(userPrincipal);
        this.host = requireNonWildcard(host);
        this.operation = requireNoneOf(
                operation,
                AclOperation.UNKNOWN, AclOperation.ALL, AclOperation.ANY);
        this.resourceType = requireNoneOf(
                resourceType,
                ResourceType.UNKNOWN, ResourceType.ANY);
        this.resourceName = requireNonWildcard(resourceName);
    }
}
