package com.mayreh.kalc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.function.Consumer;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;
import org.junit.Test;

import com.microsoft.z3.Context;

public class SpecFormulaTest {
    @Test
    public void testAllow() {
        withEncoder(encoder -> {
            SpecFormula formula = new SpecFormula(
                    encoder,
                    AclSpec.fromAclBindings(Arrays.asList(
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("admin")
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.ALL)
                                    .build(),
                            AclBindingBuilder
                                    .allow()
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.DESCRIBE)
                                    .build(),
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("foo-producer")
                                    .literal(ResourceType.TOPIC, "foo-topic")
                                    .operation(AclOperation.WRITE)
                                    .build()))
            );

            assertTrue(formula.satisfy(
                    new SpecFormula(encoder, AclSpec.fromRequest(
                            AuthorizableRequest
                                    .builder()
                                    .userPrincipal("foo-producer")
                                    .host("127.0.0.1")
                                    .operation(AclOperation.WRITE)
                                    .resourceType(ResourceType.TOPIC)
                                    .resourceName("foo-topic")
                                    .build()))
            ).satisfiable());
            assertTrue(formula.satisfy(
                    new SpecFormula(encoder, AclSpec.fromRequest(
                            AuthorizableRequest
                                    .builder()
                                    .userPrincipal("foo-producer")
                                    .host("127.0.0.1")
                                    .operation(AclOperation.DESCRIBE)
                                    .resourceType(ResourceType.TOPIC)
                                    .resourceName("foo-topic")
                                    .build()))
            ).satisfiable());
            assertFalse(formula.satisfy(
                    new SpecFormula(encoder, AclSpec.fromRequest(
                            AuthorizableRequest
                                    .builder()
                                    .userPrincipal("foo-producer")
                                    .host("127.0.0.1")
                                    .operation(AclOperation.WRITE)
                                    .resourceType(ResourceType.TOPIC)
                                    .resourceName("bar-topic")
                            .build()))
            ).satisfiable());
        });
    }

    @Test
    public void testDeny() {
        withEncoder(encoder -> {
            SpecFormula formula = new SpecFormula(
                    encoder,
                    AclSpec.fromAclBindings(Arrays.asList(
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("admin")
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.ALL)
                                    .build(),
                            AclBindingBuilder
                                    .allow()
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.DESCRIBE)
                                    .build(),
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("foo-producer")
                                    .literal(ResourceType.TOPIC, "foo-topic")
                                    .operation(AclOperation.WRITE)
                                    .build(),
                            AclBindingBuilder
                                    .deny()
                                    .userPrincipal("*")
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.ALL)
                                    .build()
            )));

            assertFalse(formula.satisfy(
                    new SpecFormula(
                            encoder,
                            AclSpec.fromRequest(
                                    AuthorizableRequest
                                            .builder()
                                            .userPrincipal("foo-producer")
                                            .host("127.0.0.1")
                                            .operation(AclOperation.WRITE)
                                            .resourceType(ResourceType.TOPIC)
                                            .resourceName("foo-topic")
                                            .build()))
            ).satisfiable());
        });
    }

    @Test
    public void testPermissive() {
        withEncoder(encoder -> {
            SpecFormula formula = new SpecFormula(
                    encoder,
                    AclSpec.fromAclBindings(
                            Arrays.asList(
                                    AclBindingBuilder
                                            .allow()
                                            .userPrincipal("admin")
                                            .literal(ResourceType.TOPIC, "*")
                                            .operation(AclOperation.ALL)
                                            .build(),
                                    AclBindingBuilder
                                            .allow()
                                            .literal(ResourceType.TOPIC, "*")
                                            .operation(AclOperation.DESCRIBE)
                                            .build(),
                                    AclBindingBuilder
                            .allow()
                            .userPrincipal("foo-producer")
                            .literal(ResourceType.TOPIC, "foo-topic")
                            .operation(AclOperation.WRITE)
                            .build()
            )));

            SpecFormula otherFormula = new SpecFormula(
                    encoder,
                    AclSpec.fromAclBindings(Arrays.asList(
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("admin")
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.ALL)
                                    .build())));

            assertTrue(formula.permissiveThan(otherFormula).permissive());
        });
    }

    @Test
    public void testNotPermissive() {
        withEncoder(encoder -> {
            SpecFormula formula = new SpecFormula(
                    encoder,
                    AclSpec.fromAclBindings(Arrays.asList(
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("admin")
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.ALL)
                                    .build(),
                            AclBindingBuilder
                                    .allow()
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.DESCRIBE)
                                    .build(),
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("foo-producer")
                                    .literal(ResourceType.TOPIC, "foo-topic")
                                    .operation(AclOperation.WRITE)
                                    .build()
                    )));

            SpecFormula otherFormula = new SpecFormula(
                    encoder,
                    AclSpec.fromAclBindings(Arrays.asList(
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("*")
                                    .literal(ResourceType.TOPIC, "foo-topic")
                                    .operation(AclOperation.WRITE)
                                    .build())));

            assertFalse(formula.permissiveThan(otherFormula).permissive());
        });
    }

    private static void withEncoder(Consumer<AclEncoder> op) {
        try (Context context = new Context()) {
            op.accept(new AclEncoder(context));
        }
    }
}
