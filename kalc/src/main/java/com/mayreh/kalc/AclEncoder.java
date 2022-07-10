package com.mayreh.kalc;

import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourceType;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.CharSort;
import com.microsoft.z3.Context;
import com.microsoft.z3.EnumSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.SeqSort;

public class AclEncoder {
    static final String WILDCARD = "*";
    static final String WILDCARD_USER = "User:" + WILDCARD;

    private final Context context;
    private final TypedEnumSort<ResourceType> resourceTypeSort;
    private final TypedEnumSort<AclOperation> aclOperationSort;
    private final Expr<SeqSort<CharSort>> principal;
    private final Expr<SeqSort<CharSort>> host;
    private final Expr<EnumSort<AclOperation>> aclOperation;
    private final Expr<EnumSort<ResourceType>> resourceType;
    private final Expr<SeqSort<CharSort>> resourceName;

    public AclEncoder(Context context) {
        this.context = context;
        resourceTypeSort = TypedEnumSort.mkSort(context, ResourceType.class);
        aclOperationSort = TypedEnumSort.mkSort(context, AclOperation.class);

        principal = context.mkConst("principal", context.getStringSort());
        host = context.mkConst("host", context.getStringSort());
        resourceName = context.mkConst("resourceName", context.getStringSort());
        resourceType = context.mkConst("resourceType", resourceTypeSort.sort());
        aclOperation = context.mkConst("operation", aclOperationSort.sort());
    }

    public BoolExpr encode(AclBinding acl) {
        BoolExpr principalExpr =
                WILDCARD_USER.equals(acl.entry().principal()) ?
                context.mkTrue() : context.mkEq(principal, context.mkString(acl.entry().principal()));
        BoolExpr hostExpr =
                WILDCARD.equals(acl.entry().host()) ?
                context.mkTrue() : context.mkEq(host, context.mkString(acl.entry().host()));
        BoolExpr operationExpr =
                AclOperation.ALL == acl.entry().operation() ?
                context.mkTrue() : context.mkEq(aclOperation, aclOperationSort.getConst(acl.entry().operation()));
        BoolExpr resourceTypeExpr =
                context.mkEq(resourceType, resourceTypeSort.getConst(acl.pattern().resourceType()));

        final BoolExpr resourceNameExpr;
        if (PatternType.PREFIXED == acl.pattern().patternType()) {
            resourceNameExpr = context.mkPrefixOf(context.mkString(acl.pattern().name()), resourceName);
        } else {
            resourceNameExpr =
                    WILDCARD.equals(acl.pattern().name()) ?
                    context.mkTrue() : context.mkEq(resourceName, context.mkString(acl.pattern().name()));
        }

        BoolExpr expr = context.mkAnd(
                principalExpr,
                hostExpr,
                operationExpr,
                resourceTypeExpr,
                resourceNameExpr);

        if (acl.entry().permissionType() == AclPermissionType.DENY) {
            return context.mkNot(expr);
        }
        return expr;
    }

    public BoolExpr encode(AuthorizableRequest request) {
        BoolExpr principalExpr =
                context.mkEq(principal, context.mkString(request.principal()));
        BoolExpr hostExpr =
                context.mkEq(host, context.mkString(request.host()));
        BoolExpr operationExpr =
                context.mkEq(aclOperation, aclOperationSort.getConst(request.operation()));
        BoolExpr resourceTypeExpr =
                context.mkEq(resourceType, resourceTypeSort.getConst(request.resourceType()));
        BoolExpr resourceNameExpr =
                context.mkEq(resourceName, context.mkString(request.resourceName()));

        return context.mkAnd(
                principalExpr,
                hostExpr,
                operationExpr,
                resourceTypeExpr,
                resourceNameExpr);
    }
}
