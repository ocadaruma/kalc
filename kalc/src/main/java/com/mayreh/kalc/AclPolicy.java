package com.mayreh.kalc;

import static com.mayreh.kalc.Utils.requireNoneOf;
import static java.util.Collections.singletonList;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.resource.PatternType;

import com.mayreh.kalc.AclConstraint.AclOperationCondition;
import com.mayreh.kalc.AclConstraint.EqualityOperator;
import com.mayreh.kalc.AclConstraint.ResourceCondition;
import com.mayreh.kalc.AclConstraint.StringCondition;
import com.mayreh.kalc.AclConstraint.StringOperator;
import com.mayreh.kalc.AclPolicy.Entry.PermissionType;

import lombok.NonNull;
import lombok.Value;
import lombok.experimental.Accessors;

/**
 * Represents an ACL policy, a set of request-tuples that are considered to be authorized.
 */
@Value
@Accessors(fluent = true)
public class AclPolicy {
    private static final String USER_PREFIX = "User:";

    List<Entry> entries;

    @Value
    @Accessors(fluent = true)
    public static class Entry {
        @NonNull
        PermissionType permission;

        @NonNull
        AclConstraint constraint;

        public enum PermissionType {
            Allow,
            Deny,
        }
    }

    /**
     * Instantiate the {@link AclPolicy} from the collection of {@link AclBinding},
     * which may be retrieved from Kafka Admin API.
     */
    public static AclPolicy fromAclBindings(Collection<AclBinding> bindings) {
        List<Entry> entries = new ArrayList<>();
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
            final StringOperator resourceNameOp;
            if (patternType == PatternType.PREFIXED) {
                resourceNameOp = StringOperator.StartWith;
            } else {
                resourceNameOp = StringOperator.In;
            }

            Entry entry = new Entry(
                    permissionType,
                    new AclConstraint(
                            new StringCondition(
                                    false, StringOperator.In, singletonList(userPrincipal)),
                            new StringCondition(
                                    false, StringOperator.In, singletonList(accessControlEntry.host())),
                            new AclOperationCondition(
                                    EqualityOperator.Eq, accessControlEntry.operation()),
                            new ResourceCondition(
                                    binding.pattern().resourceType(),
                                    new StringCondition(false,
                                                        resourceNameOp,
                                                        singletonList(binding.pattern().name())))
                    ));
            entries.add(entry);
        }
        return new AclPolicy(entries);
    }
}
