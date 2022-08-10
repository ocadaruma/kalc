package com.mayreh.kalc;

import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import com.mayreh.kalc.AclConstraint.AclOperationCondition;
import com.mayreh.kalc.AclConstraint.EqualityOperator;
import com.mayreh.kalc.AclConstraint.ResourceCondition;
import com.mayreh.kalc.AclConstraint.StringCondition;
import com.mayreh.kalc.AclConstraint.StringOperator;

/**
 * Provides handy APIs to build {@link AclConstraint} instance.
 */
public final class AclConstraintBuilder {
    public static class StringConditionBuilder {
        private boolean negate;
        private StringOperator op;
        private List<String> value;

        public StringConditionBuilder startWith(String... value) {
            op = StringOperator.StartWith;
            this.value = Arrays.asList(value);
            return this;
        }

        public StringConditionBuilder endWith(String... value) {
            op = StringOperator.EndWith;
            this.value = Arrays.asList(value);
            return this;
        }

        public StringConditionBuilder contain(String... value) {
            op = StringOperator.Contain;
            this.value = Arrays.asList(value);
            return this;
        }

        public StringConditionBuilder in(String... value) {
            op = StringOperator.In;
            this.value = Arrays.asList(value);
            return this;
        }

        public StringConditionBuilder negate() {
            negate = true;
            return this;
        }

        public StringCondition build() {
            return new StringCondition(negate, op, value);
        }
    }

    private StringCondition userPrincipal;
    private StringCondition host;
    private AclOperationCondition operation;
    private ResourceCondition resource;

    public AclConstraintBuilder userPrincipal(Consumer<StringConditionBuilder> b) {
        StringConditionBuilder builder = new StringConditionBuilder();
        b.accept(builder);
        userPrincipal = builder.build();
        return this;
    }

    public AclConstraintBuilder host(Consumer<StringConditionBuilder> b) {
        StringConditionBuilder builder = new StringConditionBuilder();
        b.accept(builder);
        host = builder.build();
        return this;
    }

    public AclConstraintBuilder operation(AclOperation operation) {
        this.operation = new AclOperationCondition(EqualityOperator.Eq, operation);
        return this;
    }

    public AclConstraintBuilder notOperation(AclOperation operation) {
        this.operation = new AclOperationCondition(EqualityOperator.NotEq, operation);
        return this;
    }

    public AclConstraintBuilder resource(ResourceType resourceType,
                                         Consumer<StringConditionBuilder> b) {
        StringConditionBuilder builder = new StringConditionBuilder();
        b.accept(builder);
        resource = new ResourceCondition(resourceType, builder.build());
        return this;
    }

    public AclConstraint build() {
        return new AclConstraint(userPrincipal, host, operation, resource);
    }
}
