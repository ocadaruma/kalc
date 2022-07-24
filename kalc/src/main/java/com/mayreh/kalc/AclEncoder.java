package com.mayreh.kalc;

import java.util.ArrayList;
import java.util.List;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import com.mayreh.kalc.AclEntry.OperationCondition;
import com.mayreh.kalc.AclEntry.PermissionType;
import com.mayreh.kalc.AclEntry.ResourceTypeCondition;
import com.mayreh.kalc.AclEntry.StringCondition;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.CharSort;
import com.microsoft.z3.Context;
import com.microsoft.z3.EnumSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.SeqSort;

import lombok.Getter;
import lombok.experimental.Accessors;

public class AclEncoder implements AutoCloseable {
    @Getter
    @Accessors(fluent = true)
    private final Context context;
    private final TypedEnumSort<ResourceType> resourceTypeSort;
    private final TypedEnumSort<AclOperation> aclOperationSort;
    private final Expr<SeqSort<CharSort>> userPrincipal;
    private final Expr<SeqSort<CharSort>> host;
    private final Expr<EnumSort<AclOperation>> aclOperation;
    private final Expr<EnumSort<ResourceType>> resourceType;
    private final Expr<SeqSort<CharSort>> resourceName;

    public AclEncoder() {
        context = new Context();
        resourceTypeSort = TypedEnumSort.mkSort(context, ResourceType.class);
        aclOperationSort = TypedEnumSort.mkSort(context, AclOperation.class);

        userPrincipal = context.mkConst("userPrincipal", context.getStringSort());
        host = context.mkConst("host", context.getStringSort());
        resourceName = context.mkConst("resourceName", context.getStringSort());
        resourceType = context.mkConst("resourceType", resourceTypeSort.sort());
        aclOperation = context.mkConst("operation", aclOperationSort.sort());
    }

    public BoolExpr encode(AclSpec spec) {
        List<BoolExpr> allow = new ArrayList<>();
        List<BoolExpr> deny = new ArrayList<>();

        for (AclEntry entry : spec.entries()) {
            switch (entry.permission()) {
                case Allow:
                    allow.add(encode(entry));
                    break;
                case Deny:
                    deny.add(encode(entry));
                    break;
            }
        }

        return context.mkAnd(
                context.mkOr(allow.stream().toArray(BoolExpr[]::new)),
                context.mkAnd(deny.stream().toArray(BoolExpr[]::new)));
    }

    public BoolExpr encode(AclEntry entry) {
        BoolExpr userPrincipalExpr = encode(userPrincipal, entry.userPrincipal());
        BoolExpr hostExpr = encode(host, entry.host());
        BoolExpr operationExpr = encode(entry.operation());
        BoolExpr resourceTypeExpr = encode(entry.resourceType());
        BoolExpr resourceNameExpr = encode(resourceName, entry.resourceName());

        BoolExpr expr = context.mkAnd(
                userPrincipalExpr,
                hostExpr,
                operationExpr,
                resourceTypeExpr,
                resourceNameExpr);

        if (entry.permission() == PermissionType.Deny) {
            return context.mkNot(expr);
        }
        return expr;
    }

    private BoolExpr encode(OperationCondition condition) {
        if (condition.value() == AclOperation.ALL) {
            if (condition.op() == OperationCondition.Operator.Eq) {
                return context.mkTrue();
            } else {
                return context.mkFalse();
            }
        } else {
            BoolExpr expr = context.mkEq(aclOperation, aclOperationSort.getConst(condition.value()));
            if (condition.op() == OperationCondition.Operator.NotEq) {
                return context.mkNot(expr);
            }
            return expr;
        }
    }

    private BoolExpr encode(ResourceTypeCondition condition) {
        BoolExpr expr = context.mkEq(resourceType, resourceTypeSort.getConst(condition.value()));
        if (condition.op() == ResourceTypeCondition.Operator.NotEq) {
            return context.mkNot(expr);
        }
        return expr;
    }

    private BoolExpr encode(
            Expr<SeqSort<CharSort>> expr,
            StringCondition condition) {
        if (AclSpec.WILDCARD.equals(condition.value())) {
            if (condition.op() == StringCondition.Operator.NotEq) {
                return context.mkFalse();
            } else {
                return context.mkTrue();
            }
        } else {
            switch (condition.op()) {
                case Eq:
                    return context.mkEq(expr, context.mkString(condition.value()));
                case NotEq:
                    return context.mkNot(context.mkEq(expr, context.mkString(condition.value())));
                case StartWith:
                    return context.mkPrefixOf(context.mkString(condition.value()), expr);
                case EndWith:
                    return context.mkSuffixOf(context.mkString(condition.value()), expr);
                case Contains:
                    return context.mkContains(expr, context.mkString(condition.value()));
            }
        }
        throw new RuntimeException("Never happen");
    }

    @Override
    public void close() {
        context.close();
    }
}
