package com.mayreh.kalc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.function.Consumer;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;
import org.junit.Test;

import com.mayreh.kalc.AclPolicy.ComparisonResult;
import com.microsoft.z3.Context;

public class AclPolicyTest {
    @Test
    public void testAllow() {
        inContext(ctx -> {
            AclEncoder encoder = new AclEncoder(ctx);
            AclPolicy policy = new AclPolicy(ctx, encoder, Arrays.asList(
                    AclBindingBuilder
                            .allow()
                            .user("admin")
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
                            .user("foo-producer")
                            .literal(ResourceType.TOPIC, "foo-topic")
                            .operation(AclOperation.WRITE)
                            .build()));

            assertTrue(policy.allow(
                    AuthorizableRequest
                            .builder()
                            .principal("User:foo-producer")
                            .host("127.0.0.1")
                            .operation(AclOperation.WRITE)
                            .resourceType(ResourceType.TOPIC)
                            .resourceName("foo-topic")
                            .build()));
            assertTrue(policy.allow(
                    AuthorizableRequest
                            .builder()
                            .principal("User:foo-producer")
                            .host("127.0.0.1")
                            .operation(AclOperation.DESCRIBE)
                            .resourceType(ResourceType.TOPIC)
                            .resourceName("foo-topic")
                            .build()));
            assertFalse(policy.allow(
                    AuthorizableRequest
                            .builder()
                            .principal("User:foo-producer")
                            .host("127.0.0.1")
                            .operation(AclOperation.WRITE)
                            .resourceType(ResourceType.TOPIC)
                            .resourceName("bar-topic")
                            .build()));
        });
    }

    @Test
    public void testDeny() {
        inContext(ctx -> {
            AclEncoder encoder = new AclEncoder(ctx);
            AclPolicy policy = new AclPolicy(ctx, encoder, Arrays.asList(
                    AclBindingBuilder
                            .allow()
                            .user("admin")
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
                            .user("foo-producer")
                            .literal(ResourceType.TOPIC, "foo-topic")
                            .operation(AclOperation.WRITE)
                            .build(),
                    AclBindingBuilder
                            .deny()
                            .user("*")
                            .literal(ResourceType.TOPIC, "*")
                            .operation(AclOperation.ALL)
                            .build()
            ));

            assertFalse(policy.allow(
                    AuthorizableRequest
                            .builder()
                            .principal("User:foo-producer")
                            .host("127.0.0.1")
                            .operation(AclOperation.WRITE)
                            .resourceType(ResourceType.TOPIC)
                            .resourceName("foo-topic")
                            .build()));
        });
    }

    @Test
    public void testPermissive() {
        inContext(ctx -> {
            AclEncoder encoder = new AclEncoder(ctx);
            AclPolicy policy = new AclPolicy(ctx, encoder, Arrays.asList(
                    AclBindingBuilder
                            .allow()
                            .user("admin")
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
                            .user("foo-producer")
                            .literal(ResourceType.TOPIC, "foo-topic")
                            .operation(AclOperation.WRITE)
                            .build()
            ));

            AclPolicy otherPolicy = new AclPolicy(ctx, encoder, Arrays.asList(
                    AclBindingBuilder
                            .allow()
                            .user("admin")
                            .literal(ResourceType.TOPIC, "*")
                            .operation(AclOperation.ALL)
                            .build()));

            assertTrue(policy.permissiveThan(otherPolicy).permissive());
        });
    }

    @Test
    public void testNotPermissive() {
        inContext(ctx -> {
            AclEncoder encoder = new AclEncoder(ctx);
            AclPolicy policy = new AclPolicy(ctx, encoder, Arrays.asList(
                    AclBindingBuilder
                            .allow()
                            .user("admin")
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
                            .user("foo-producer")
                            .literal(ResourceType.TOPIC, "foo-topic")
                            .operation(AclOperation.WRITE)
                            .build()
            ));

            AclPolicy otherPolicy = new AclPolicy(ctx, encoder, Arrays.asList(
                    AclBindingBuilder
                            .allow()
                            .user("*")
                            .literal(ResourceType.TOPIC, "foo-topic")
                            .operation(AclOperation.WRITE)
                            .build()));

            ComparisonResult result = policy.permissiveThan(otherPolicy);
            assertFalse(result.permissive());
        });
    }

    private static void inContext(Consumer<Context> op) {
        try (Context context = new Context()) {
            op.accept(context);
        }
    }
}
