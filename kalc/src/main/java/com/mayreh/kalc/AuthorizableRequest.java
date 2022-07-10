package com.mayreh.kalc;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import lombok.Builder;
import lombok.Value;
import lombok.experimental.Accessors;

@Value
@Builder
@Accessors(fluent = true)
public class AuthorizableRequest {
    String principal;
    String host;
    AclOperation operation;
    ResourceType resourceType;
    String resourceName;
}
