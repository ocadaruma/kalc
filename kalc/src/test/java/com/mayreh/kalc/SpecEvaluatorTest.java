package com.mayreh.kalc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.function.Consumer;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;
import org.junit.Test;

import com.mayreh.kalc.SpecEvaluator.Permissiveness;
import com.microsoft.z3.Context;

public class SpecEvaluatorTest {
    @Test
    public void testAllow() {
        inContext(ctx -> {
            AclEncoder encoder = new AclEncoder(ctx);
            SpecEvaluator evaluator = new SpecEvaluator(
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

            assertTrue(evaluator.satisfy(
                    new SpecEvaluator(encoder, AclSpec.fromRequest(
                            AuthorizableRequest
                                    .builder()
                                    .userPrincipal("foo-producer")
                                    .host("127.0.0.1")
                                    .operation(AclOperation.WRITE)
                                    .resourceType(ResourceType.TOPIC)
                                    .resourceName("foo-topic")
                                    .build()))
            ).satisfiable());
            assertTrue(evaluator.satisfy(
                    new SpecEvaluator(encoder, AclSpec.fromRequest(
                            AuthorizableRequest
                                    .builder()
                                    .userPrincipal("foo-producer")
                                    .host("127.0.0.1")
                                    .operation(AclOperation.DESCRIBE)
                                    .resourceType(ResourceType.TOPIC)
                                    .resourceName("foo-topic")
                                    .build()))
            ).satisfiable());
            assertFalse(evaluator.satisfy(
                    new SpecEvaluator(encoder, AclSpec.fromRequest(
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
        inContext(ctx -> {
            AclEncoder encoder = new AclEncoder(ctx);
            SpecEvaluator evaluator = new SpecEvaluator(
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

            assertFalse(evaluator.satisfy(
                    new SpecEvaluator(
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
        inContext(ctx -> {
            AclEncoder encoder = new AclEncoder(ctx);
            SpecEvaluator evaluator = new SpecEvaluator(
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

            SpecEvaluator otherEvaluator = new SpecEvaluator(
                    encoder,
                    AclSpec.fromAclBindings(Arrays.asList(
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("admin")
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.ALL)
                                    .build())));

            assertTrue(evaluator.permissiveThan(otherEvaluator).permissive());
        });
    }

    @Test
    public void testNotPermissive() {
        inContext(ctx -> {
            AclEncoder encoder = new AclEncoder(ctx);
            SpecEvaluator evaluator = new SpecEvaluator(
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

            SpecEvaluator otherEvaluator = new SpecEvaluator(
                    encoder,
                    AclSpec.fromAclBindings(Arrays.asList(
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("*")
                                    .literal(ResourceType.TOPIC, "foo-topic")
                                    .operation(AclOperation.WRITE)
                                    .build())));

            Permissiveness result = evaluator.permissiveThan(otherEvaluator);
            assertFalse(result.permissive());
        });
    }

    private static void inContext(Consumer<Context> op) {
        try (Context context = new Context()) {
            op.accept(context);
        }
    }
}
