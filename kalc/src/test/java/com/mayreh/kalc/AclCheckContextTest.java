package com.mayreh.kalc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.function.Consumer;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;
import org.junit.Test;

public class AclCheckContextTest {
    @Test
    public void testAllow() {
        withContext(ctx -> {
            AclPolicy policy = AclPolicy.fromAclBindings(
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
                                    .build())
            );

            assertTrue(ctx.intersection(
                    policy,
                    new AclConstraintBuilder()
                            .userPrincipal(u -> u.in("foo-producer"))
                            .host(h -> h.in("127.0.0.1"))
                            .operation(AclOperation.WRITE)
                            .resource(ResourceType.TOPIC, r -> r.in("foo-topic"))
                            .build().toPolicy()).intersects());
            assertTrue(ctx.intersection(
                    policy,
                    new AclConstraintBuilder()
                            .userPrincipal(u -> u.in("foo-producer"))
                            .host(h -> h.in("127.0.0.1"))
                            .operation(AclOperation.DESCRIBE)
                            .resource(ResourceType.TOPIC, r -> r.in("foo-topic"))
                            .build().toPolicy()).intersects());
            assertFalse(ctx.intersection(
                    policy,
                    new AclConstraintBuilder()
                            .userPrincipal(u -> u.in("foo-producer"))
                            .host(h -> h.in("127.0.0.1"))
                            .operation(AclOperation.WRITE)
                            .resource(ResourceType.TOPIC, r -> r.in("bar-topic"))
                            .build().toPolicy()).intersects());
        });
    }

    @Test
    public void testDeny() {
        withContext(ctx -> {
            AclPolicy policy = AclPolicy.fromAclBindings(
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
                                    .build(),
                            AclBindingBuilder
                                    .deny()
                                    .userPrincipal("*")
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.ALL)
                                    .build())
            );

            assertFalse(ctx.intersection(
                    policy,
                    new AclConstraintBuilder()
                            .userPrincipal(u -> u.in("foo-producer"))
                            .host(h -> h.in("127.0.0.1"))
                            .operation(AclOperation.WRITE)
                            .resource(ResourceType.TOPIC, r -> r.in("foo-topic"))
                            .build().toPolicy()).intersects());
        });
    }

    @Test
    public void testPermissive() {
        withContext(ctx -> {
            AclPolicy policy = AclPolicy.fromAclBindings(
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
                            .build())
            );

            AclPolicy otherPolicy = AclPolicy.fromAclBindings(
                    Arrays.asList(
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("admin")
                                    .literal(ResourceType.TOPIC, "*")
                                    .operation(AclOperation.ALL)
                                    .build()));

            assertTrue(ctx.supersetOf(policy, otherPolicy).isSuperset());
        });
    }

    @Test
    public void testNotPermissive() {
        withContext(ctx -> {
            AclPolicy policy = AclPolicy.fromAclBindings(
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
                                    .build())
            );

            AclPolicy otherPolicy = AclPolicy.fromAclBindings(
                    Arrays.asList(
                            AclBindingBuilder
                                    .allow()
                                    .userPrincipal("*")
                                    .literal(ResourceType.TOPIC, "foo-topic")
                                    .operation(AclOperation.WRITE)
                                    .build()));

            assertFalse(ctx.supersetOf(policy, otherPolicy).isSuperset());
        });
    }

    private static void withContext(Consumer<AclCheckContext> op) {
        try (AclCheckContext ctx = new AclCheckContext()) {
            op.accept(ctx);
        }
    }
}
