package com.mayreh.kalc;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import com.mayreh.kalc.AclConstraint.AclOperationCondition;
import com.mayreh.kalc.AclConstraint.EqualityOperator;
import com.mayreh.kalc.AclConstraint.ResourceCondition;
import com.mayreh.kalc.AclConstraint.StringCondition;
import com.mayreh.kalc.RequestTuple.RequestTupleBuilder;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.CharSort;
import com.microsoft.z3.Context;
import com.microsoft.z3.EnumSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.Model;
import com.microsoft.z3.SeqSort;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Status;

import lombok.NonNull;
import lombok.Value;
import lombok.experimental.Accessors;

public class AclCheckContext implements AutoCloseable {
    @Value
    @Accessors(fluent = true)
    public static class IntersectionResult {
        boolean intersects;

        @NonNull
        Optional<RequestTuple> example;
    }

    @Value
    @Accessors(fluent = true)
    public static class SupersetResult {
        boolean isSuperset;

        @NonNull
        Optional<RequestTuple> counterexample;
    }

    private static final String USER_PRINCIPAL = "userPrincipal";
    private static final String HOST = "host";
    private static final String OPERATION = "operation";
    private static final String RESOURCE_TYPE = "resourceType";
    private static final String RESOURCE_NAME = "resourceName";

    private final Context context;
    private final TypedEnumSort<ResourceType> resourceTypeSort;
    private final TypedEnumSort<AclOperation> aclOperationSort;
    private final Expr<SeqSort<CharSort>> userPrincipal;
    private final Expr<SeqSort<CharSort>> host;
    private final Expr<EnumSort<AclOperation>> aclOperation;
    private final Expr<EnumSort<ResourceType>> resourceType;
    private final Expr<SeqSort<CharSort>> resourceName;

    public AclCheckContext() {
        context = new Context();
        resourceTypeSort = TypedEnumSort.mkSort(context, ResourceType.class);
        aclOperationSort = TypedEnumSort.mkSort(context, AclOperation.class);

        userPrincipal = context.mkConst(USER_PRINCIPAL, context.getStringSort());
        host = context.mkConst(HOST, context.getStringSort());
        aclOperation = context.mkConst(OPERATION, aclOperationSort.sort());
        resourceType = context.mkConst(RESOURCE_TYPE, resourceTypeSort.sort());
        resourceName = context.mkConst(RESOURCE_NAME, context.getStringSort());
    }

    /**
     * Check if two policies intersect.
     * Returns the example of the request-tuple if intersects.
     */
    public IntersectionResult intersection(AclPolicy p1, AclPolicy p2) {
        Solver solver = context.mkSolver();
        solver.add(encode(p1), encode(p2));
        Status status = solver.check();

        if (status == Status.SATISFIABLE) {
            return new IntersectionResult(true, Optional.of(buildExample(solver.getModel())));
        }
        return new IntersectionResult(false, Optional.empty());
    }

    /**
     * Check if p1 is the superset of p2.
     * Returns counterexample if p1 is not a superset of p2.
     * (i.e. there's a request-tuple which p2 contains and p1 doesn't contain)
     */
    public SupersetResult supersetOf(AclPolicy p1, AclPolicy p2) {
        Solver solver = context.mkSolver();
        solver.add(context.mkNot(encode(p1)), encode(p2));

        Status status = solver.check();
        if (status == Status.SATISFIABLE) {
            return new SupersetResult(false, Optional.of(buildExample(solver.getModel())));
        }
        return new SupersetResult(true, Optional.empty());
    }

    @Override
    public void close() {
        context.close();
    }

    private RequestTuple buildExample(Model model) {
        RequestTupleBuilder builder = RequestTuple.builder();
        for (FuncDecl<?> decl : model.getConstDecls()) {
            String str = model.getConstInterp(decl).toString();
            switch (decl.getName().toString()) {
                case USER_PRINCIPAL:
                    builder.userPrincipal(str);
                    break;
                case HOST:
                    builder.host(str);
                    break;
                case OPERATION:
                    builder.operation(AclOperation.fromString(str));
                    break;
                case RESOURCE_TYPE:
                    builder.resourceType(ResourceType.fromString(str));
                    break;
                case RESOURCE_NAME:
                    builder.resourceName(str);
                    break;
            }
        }
        return builder.build();
    }

    private BoolExpr encode(AclPolicy policy) {
        List<BoolExpr> allow = new ArrayList<>();
        List<BoolExpr> deny = new ArrayList<>();

        for (AclPolicy.Entry entry : policy.entries()) {
            switch (entry.permission()) {
                case Allow:
                    allow.add(encode(entry.constraint()));
                    break;
                case Deny:
                    deny.add(context.mkNot(encode(entry.constraint())));
                    break;
            }
        }

        return context.mkAnd(
                context.mkOr(allow.stream().toArray(BoolExpr[]::new)),
                context.mkAnd(deny.stream().toArray(BoolExpr[]::new)));
    }

    private BoolExpr encode(AclConstraint constraint) {
        BoolExpr userPrincipalExpr = encode(userPrincipal, constraint.userPrincipal());
        BoolExpr hostExpr = encode(host, constraint.host());
        BoolExpr operationExpr = encode(constraint.operation());
        BoolExpr resourceExpr = encode(constraint.resource());

        return context.mkAnd(
                userPrincipalExpr,
                hostExpr,
                operationExpr,
                resourceExpr);
    }

    private BoolExpr encode(AclOperationCondition condition) {
        if (condition.value() == AclOperation.ALL) {
            return condition.op() == EqualityOperator.Eq ? context.mkTrue() : context.mkFalse();
        } else {
            BoolExpr expr = context.mkEq(aclOperation, aclOperationSort.getConst(condition.value()));
            return condition.op() == EqualityOperator.Eq ? expr : context.mkNot(expr);
        }
    }

    private BoolExpr encode(ResourceCondition condition) {
        return context.mkAnd(
                context.mkEq(resourceType, resourceTypeSort.getConst(condition.resourceType())),
                encode(resourceName, condition.resourceName()));
    }

    private BoolExpr encode(
            Expr<SeqSort<CharSort>> expr,
            StringCondition condition) {
        if (condition.value().contains(AclConstraint.WILDCARD)) {
            return condition.negate() ? context.mkFalse() : context.mkTrue();
        }

        final Function<Stream<BoolExpr>, BoolExpr> combiner;
        if (condition.negate()) {
            combiner = exprs -> context.mkAnd(
                    exprs.map(context::mkNot).toArray(BoolExpr[]::new));
        } else {
            combiner = exprs -> context.mkOr(
                    exprs.toArray(BoolExpr[]::new));
        }

        switch (condition.op()) {
            case StartWith:
                return combiner.apply(
                        condition.value()
                                 .stream()
                                 .map(v -> context.mkPrefixOf(context.mkString(v), expr)));
            case EndWith:
                return combiner.apply(
                        condition.value()
                                 .stream()
                                 .map(v -> context.mkSuffixOf(context.mkString(v), expr)));
            case Contain:
                return combiner.apply(
                        condition.value()
                                 .stream()
                                 .map(v -> context.mkContains(expr, context.mkString(v))));
            case In:
                return combiner.apply(
                        condition.value()
                                 .stream()
                                 .map(v -> context.mkEq(expr, context.mkString(v))));
        }
        throw new RuntimeException("Never happen");
    }
}
