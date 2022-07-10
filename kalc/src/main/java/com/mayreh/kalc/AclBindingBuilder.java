package com.mayreh.kalc;

import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

/**
 * Provides handy APIs to build {@link AclBinding} instance.
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class AclBindingBuilder {
    private final AclPermissionType type;
    @Setter
    @Accessors(fluent = true)
    private String host = AclEncoder.WILDCARD;
    private String principal = AclEncoder.WILDCARD_USER;
    @Setter
    @Accessors(fluent = true)
    private AclOperation operation;
    private PatternType resourcePatternType;
    private ResourceType resourceType;
    private String resourceName;

    public static AclBindingBuilder allow() {
        return new AclBindingBuilder(AclPermissionType.ALLOW);
    }

    public static AclBindingBuilder deny() {
        return new AclBindingBuilder(AclPermissionType.DENY);
    }

    public AclBindingBuilder user(String name) {
        principal = "User:" + name;
        return this;
    }

    public AclBindingBuilder prefixed(ResourceType resourceType, String prefix) {
        this.resourceType = resourceType;
        resourcePatternType = PatternType.PREFIXED;
        resourceName = prefix;
        return this;
    }

    public AclBindingBuilder literal(ResourceType resourceType, String name) {
        this.resourceType = resourceType;
        resourcePatternType = PatternType.LITERAL;
        resourceName = name;
        return this;
    }

    public AclBinding build() {
        ResourcePattern resourcePattern = new ResourcePattern(
                resourceType,
                resourceName,
                resourcePatternType);
        AccessControlEntry entry = new AccessControlEntry(
                principal,
                host,
                operation,
                type);
        return new AclBinding(resourcePattern, entry);
    }
}
