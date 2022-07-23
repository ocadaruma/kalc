package com.mayreh.kalc;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import lombok.Value;
import lombok.experimental.Accessors;

/**
 * Set of conditions that defines an authority entry.
 */
@Value
@Accessors(fluent = true)
public class AclEntry {
    PermissionType permission;

    StringCondition userPrincipal;

    StringCondition host;

    OperationCondition operation;

    ResourceTypeCondition resourceType;

    StringCondition resourceName;

    public enum PermissionType {
        Allow,
        Deny,
    }

    @Value
    @Accessors(fluent = true)
    public static class StringCondition {
        public enum Operator {
            Eq,
            NotEq,
            StartWith,
            EndWith,
            Contains,
        }

        Operator op;
        String value;
    }

    @Value
    @Accessors(fluent = true)
    public static class OperationCondition {
        public enum Operator {
            Eq,
            NotEq,
        }

        Operator op;
        AclOperation value;
    }

    @Value
    @Accessors(fluent = true)
    public static class ResourceTypeCondition {
        public enum Operator {
            Eq,
            NotEq,
        }

        Operator op;
        ResourceType value;
    }
}
