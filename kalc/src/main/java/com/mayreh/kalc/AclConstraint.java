package com.mayreh.kalc;

import static com.mayreh.kalc.Utils.require;
import static com.mayreh.kalc.Utils.requireNoneOf;
import static java.util.Collections.singletonList;

import java.beans.ConstructorProperties;
import java.util.List;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import com.mayreh.kalc.AclPolicy.Entry;
import com.mayreh.kalc.AclPolicy.Entry.PermissionType;

import lombok.NonNull;
import lombok.Value;
import lombok.experimental.Accessors;

/**
 * Represents a constraint over request-tuple (principal, host, operation, resourceType, resourceName),
 * which defines the subset of entire request-tuple universe.
 */
@Value
@Accessors(fluent = true)
public class AclConstraint {
    public static final String WILDCARD = "*";

    @NonNull
    StringCondition userPrincipal;

    @NonNull
    StringCondition host;

    @NonNull
    AclOperationCondition operation;

    @NonNull
    ResourceCondition resource;

    /**
     * Returns the equivalent {@link AclPolicy} that consist of single constraint
     */
    public AclPolicy toPolicy() {
        return new AclPolicy(singletonList(new Entry(PermissionType.Allow, this)));
    }

    @Value
    @Accessors(fluent = true)
    public static class StringCondition {
        boolean negate;

        @NonNull
        StringOperator op;

        @NonNull
        List<String> value;

        @ConstructorProperties({"negate", "op", "value"})
        public StringCondition(
                boolean negate,
                @NonNull StringOperator op,
                @NonNull List<String> value) {
            this.negate = negate;
            this.op = op;
            this.value = require(value, v -> !v.isEmpty(), "value must not be empty");
        }
    }

    @Value
    @Accessors(fluent = true)
    public static class AclOperationCondition {
        @NonNull
        EqualityOperator op;

        @NonNull
        AclOperation value;

        @ConstructorProperties({"op", "value"})
        public AclOperationCondition(
                @NonNull EqualityOperator op,
                @NonNull AclOperation value) {
            this.op = op;
            this.value = requireNoneOf(
                    value,
                    AclOperation.ANY,
                    AclOperation.UNKNOWN);
        }
    }

    @Value
    @Accessors(fluent = true)
    public static class ResourceCondition {
        @NonNull
        ResourceType resourceType;

        @NonNull
        StringCondition resourceName;

        @ConstructorProperties({"resourceType", "resourceName"})
        public ResourceCondition(
                @NonNull ResourceType resourceType,
                @NonNull StringCondition resourceName) {
            this.resourceType = requireNoneOf(
                    resourceType,
                    ResourceType.UNKNOWN,
                    ResourceType.ANY);
            this.resourceName = resourceName;
        }
    }

    public enum EqualityOperator {
        Eq,
        NotEq,
    }

    public enum StringOperator {
        StartWith,
        EndWith,
        Contain,
        In,
    }
}
