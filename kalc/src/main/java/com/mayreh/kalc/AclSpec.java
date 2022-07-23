package com.mayreh.kalc;

import static com.mayreh.kalc.Utils.requireNoneOf;
import static java.util.Collections.singletonList;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourceType;

import com.mayreh.kalc.AclEntry.OperationCondition;
import com.mayreh.kalc.AclEntry.PermissionType;
import com.mayreh.kalc.AclEntry.ResourceTypeCondition;
import com.mayreh.kalc.AclEntry.StringCondition;

import lombok.Value;
import lombok.experimental.Accessors;

@Value
@Accessors(fluent = true)
public class AclSpec {
    public static final String WILDCARD = "*";
    private static final String USER_PREFIX = "User:";

    List<AclEntry> entries;

    public static AclSpec fromAclBindings(Collection<AclBinding> bindings) {
        List<AclEntry> entries = new ArrayList<>();
        for (AclBinding binding : bindings) {
            AccessControlEntry accessControlEntry = binding.entry();

            final PermissionType permissionType;
            if (accessControlEntry.permissionType() == AclPermissionType.ALLOW) {
                permissionType = PermissionType.Allow;
            } else if (accessControlEntry.permissionType() == AclPermissionType.DENY) {
                permissionType = PermissionType.Deny;
            } else {
                throw new IllegalArgumentException(accessControlEntry.permissionType() + " is not allowed");
            }

            final String userPrincipal;
            if (!accessControlEntry.principal().startsWith(USER_PREFIX)) {
                throw new IllegalArgumentException("Only user principal is supported: " +
                                                   accessControlEntry.principal());
            }
            userPrincipal = accessControlEntry.principal().substring(USER_PREFIX.length());

            PatternType patternType = requireNoneOf(
                    binding.pattern().patternType(),
                    PatternType.UNKNOWN, PatternType.ANY, PatternType.MATCH);
            final StringCondition.Operator resourceNameOp;
            if (patternType == PatternType.PREFIXED) {
                resourceNameOp = StringCondition.Operator.StartWith;
            } else {
                resourceNameOp = StringCondition.Operator.Eq;
            }

            entries.add(new AclEntry(
                    permissionType,
                    new StringCondition(StringCondition.Operator.Eq, userPrincipal),
                    new StringCondition(StringCondition.Operator.Eq, accessControlEntry.host()),
                    new OperationCondition(
                            OperationCondition.Operator.Eq,
                            requireNoneOf(accessControlEntry.operation(), AclOperation.UNKNOWN, AclOperation.ANY)),
                    new ResourceTypeCondition(
                            ResourceTypeCondition.Operator.Eq,
                            requireNoneOf(binding.pattern().resourceType(), ResourceType.UNKNOWN, ResourceType.ANY)),
                    new StringCondition(resourceNameOp, binding.pattern().name()))
            );
        }
        return new AclSpec(entries);
    }

    public static AclSpec fromRequest(AuthorizableRequest request) {
        AclEntry entry = new AclEntry(
                PermissionType.Allow,
                new StringCondition(StringCondition.Operator.Eq, request.userPrincipal()),
                new StringCondition(StringCondition.Operator.Eq, request.host()),
                new OperationCondition(OperationCondition.Operator.Eq, request.operation()),
                new ResourceTypeCondition(ResourceTypeCondition.Operator.Eq, request.resourceType()),
                new StringCondition(StringCondition.Operator.Eq, request.resourceName()));

        return new AclSpec(singletonList(entry));
    }
}
