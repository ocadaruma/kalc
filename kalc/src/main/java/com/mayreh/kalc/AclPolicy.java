package com.mayreh.kalc;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.acl.AclBinding;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.Model;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Status;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import lombok.experimental.Accessors;

@RequiredArgsConstructor
public class AclPolicy {
    private final Context context;
    private final AclEncoder encoder;
    private final BoolExpr policyExpr;

    public AclPolicy(Context context,
                     AclEncoder encoder,
                     Collection<AclBinding> acls) {
        this.context = context;
        this.encoder = encoder;

        List<BoolExpr> allow = new ArrayList<>();
        List<BoolExpr> deny = new ArrayList<>();
        for (AclBinding acl : acls) {
            switch (acl.entry().permissionType()) {
                case ALLOW:
                    allow.add(encoder.encode(acl));
                    break;
                case DENY:
                    deny.add(encoder.encode(acl));
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported permission type: " +
                                                       acl.entry().permissionType());
            }
        }

        policyExpr = context.mkAnd(
                context.mkOr(allow.stream().toArray(BoolExpr[]::new)),
                context.mkAnd(deny.stream().toArray(BoolExpr[]::new)));
    }

    @Value
    @Accessors(fluent = true)
    public static class ComparisonResult {
        boolean permissive;
        @NonNull
        Map<String, String> counterexample;
    }

    public boolean allow(AuthorizableRequest request) {
        Solver solver = context.mkSolver();

        solver.add(policyExpr);
        solver.add(encoder.encode(request));

        return solver.check() == Status.SATISFIABLE;
    }

    public ComparisonResult permissiveThan(AclPolicy other) {
        Solver solver = context.mkSolver();

        solver.add(other.policyExpr);
        solver.add(context.mkNot(policyExpr));

        Status status = solver.check();

        Map<String, String> counterexample = new HashMap<>();
        if (status == Status.SATISFIABLE) {
            Model model = solver.getModel();
            for (FuncDecl<?> decl : model.getConstDecls()) {
                counterexample.put(
                        decl.getName().toString(),
                        model.getConstInterp(decl).toString());
            }
            return new ComparisonResult(false, counterexample);
        }
        return new ComparisonResult(true, counterexample);
    }
}
