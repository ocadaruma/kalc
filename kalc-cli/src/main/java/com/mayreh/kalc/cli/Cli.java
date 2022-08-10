package com.mayreh.kalc.cli;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collection;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.mayreh.kalc.AclCheckContext;
import com.mayreh.kalc.AclCheckContext.IntersectionResult;
import com.mayreh.kalc.AclCheckContext.SupersetResult;
import com.mayreh.kalc.AclPolicy;
import com.mayreh.kalc.cli.Cli.Check;
import com.mayreh.kalc.cli.Cli.Dump;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

@Command(name = "kalc",
        description = "Kafka ACL checker",
        subcommands = { Dump.class, Check.class },
        mixinStandardHelpOptions = true)
public class Cli implements Runnable {
    private static final ObjectMapper mapper = YAMLMapper
            .builder()
            .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
            .visibility(PropertyAccessor.FIELD, Visibility.ANY)
            .build();

    @Spec
    private CommandSpec spec;

    @Override
    public void run() {
        spec.commandLine().usage(System.err);
    }

    public static void main(String[] args) {
        new CommandLine(new Cli()).execute(args);
    }

    @Command(name = "dump",
            description = "Dump ACL entries in the Kafka cluster to the YAML")
    static class Dump implements IORunnable {
        @Option(names = "--bootstrap-servers",
                required = true)
        private String bootstrapServers;

        @Option(names = "--command-config")
        private File commandConfigFile;

        @Option(names = "--output",
                required = true)
        private File outputFile;

        @Override
        public void runIO() throws IOException {
            Properties props = new Properties();
            props.setProperty(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
            props.setProperty(AdminClientConfig.CLIENT_ID_CONFIG, "kalc-admin-client");

            if (commandConfigFile != null) {
                Properties commandConfig = new Properties();
                try (FileInputStream is = new FileInputStream(commandConfigFile)) {
                    commandConfig.load(is);
                }
                props.putAll(commandConfig);
            }

            try (Admin admin = Admin.create(props)) {
                Collection<AclBinding> bindings = admin.describeAcls(AclBindingFilter.ANY).values().get();
                mapper.writeValue(outputFile, AclPolicy.fromAclBindings(bindings));
            } catch (ExecutionException e) {
                throw new RuntimeException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        }
    }

    @Command(name = "check",
            description = "Check if base-policy satisfies the given expectation against target-policy")
    static class Check implements IORunnable {
        @Option(names = "--base-policy",
                required = true)
        private File basePolicyFile;

        @Option(names = "--target-policy",
                required = true)
        private File targetPolicyFile;

        @Option(names = "--check",
                required = true)
        private Expectation check;

        private enum Expectation {
            intersection,
            supersetOf,
        }

        @Override
        public void runIO() throws IOException {
            AclPolicy basePolicy = mapper.readValue(basePolicyFile, AclPolicy.class);
            AclPolicy targetPolicy = mapper.readValue(targetPolicyFile, AclPolicy.class);

            try (AclCheckContext ctx = new AclCheckContext()) {
                switch (check) {
                    case intersection:
                        IntersectionResult intersection = ctx.intersection(basePolicy, targetPolicy);
                        System.out.printf("Result  : %s\n", intersection.intersects());
                        System.out.printf("Example : %s\n", intersection.example());
                        break;
                    case supersetOf:
                        SupersetResult supersetResult = ctx.supersetOf(basePolicy, targetPolicy);
                        System.out.printf("Result          : %s\n", supersetResult.isSuperset());
                        System.out.printf("Counter Example : %s\n", supersetResult.counterexample());
                        break;
                }
            }
        }
    }

    @FunctionalInterface
    private interface IORunnable extends Runnable {
        void runIO() throws IOException;

        @Override
        default void run() {
            try {
                runIO();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
