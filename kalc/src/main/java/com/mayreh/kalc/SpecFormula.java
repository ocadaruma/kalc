package com.mayreh.kalc;

import java.util.HashMap;
import java.util.Map;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.Model;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Status;

import lombok.Value;
import lombok.experimental.Accessors;

public class SpecFormula {
    private final Context context;
    private final BoolExpr specExpr;

    public SpecFormula(AclEncoder encoder, AclSpec spec) {
        context = encoder.context();
        specExpr = encoder.encode(spec);
    }

    @Value
    @Accessors(fluent = true)
    public static class Permissiveness {
        boolean permissive;
        /**
         * The evidence this spec is less permissive than others.
         * i.e. The variable assignment that makes other spec to true while this spec to false.
         *
         * Empty if this spec is permissive than others.
         */
        Map<String, String> counterexample;
    }

    @Value
    @Accessors(fluent = true)
    public static class Satisfiability {
        boolean satisfiable;

        Map<String, String> example;
    }

    public Permissiveness permissiveThan(SpecFormula other) {
        Solver solver = context.mkSolver();

        solver.add(other.specExpr);
        solver.add(context.mkNot(specExpr));

        Status status = solver.check();

        Map<String, String> counterexample = new HashMap<>();
        if (status == Status.SATISFIABLE) {
            Model model = solver.getModel();
            for (FuncDecl<?> decl : model.getConstDecls()) {
                counterexample.put(
                        decl.getName().toString(),
                        model.getConstInterp(decl).toString());
            }
            return new Permissiveness(false, counterexample);
        }
        return new Permissiveness(true, counterexample);
    }

    public Satisfiability satisfy(SpecFormula other) {
        Solver solver = context.mkSolver();

        solver.add(specExpr);
        solver.add(other.specExpr);

        Status status = solver.check();

        Map<String, String> example = new HashMap<>();
        if (status == Status.SATISFIABLE) {
            Model model = solver.getModel();
            for (FuncDecl<?> decl : model.getConstDecls()) {
                example.put(
                        decl.getName().toString(),
                        model.getConstInterp(decl).toString());
            }
            return new Satisfiability(true, example);
        }
        return new Satisfiability(false, example);
    }
}
