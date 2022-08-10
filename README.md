# kalc

Kafka ACL checker using SMT encoding of ACL bindings.

[![CI](https://github.com/ocadaruma/kalc/actions/workflows/ci.yml/badge.svg)](https://github.com/ocadaruma/kalc/actions/workflows/ci.yml)

## Usage

You have to build CLI jar in advance.

```
$ ./gradlew :kalc-cli shadowJar
```

### Dump Kafka ACLs as the policy file

```bash
$ java -cp kalc-cli/build/libs/kalc-cli-*.jar com.mayreh.kalc.cli.Cli \
    dump --bootstrap-servers kafka-host:9092 --output policy.yml
```

### Compare the policy against another policy

Let's see the usage by examples.

For all examples, assume the content of `policy.yml` is below:

```yaml
---
entries:
- permission: Allow
  constraint:
    userPrincipal:
      negate: false
      op: In
      value: [admin]
    host:
      negate: false
      op: In
      value: ["*"]
    operation:
      op: Eq
      value: ALL
    resource:
      resourceType: CLUSTER
      resourceName:
        negate: false
        op: In
        value: ["*"]
- permission: Allow
  constraint:
    userPrincipal:
      negate: false
      op: In
      value: [foo]
    host:
      negate: false
      op: In
      value: ["*"]
    operation:
      op: Eq
      value: ALL
    resource:
      resourceType: TOPIC
      resourceName:
        negate: false
        op: In
        value: [bar]
```

#### Check the policy allows User:foo to WRITE topic:bar from host 192.0.2.1

```bash
$ cat target.yml
---
entries:
- permission: Allow
  constraint:
    userPrincipal:
      negate: false
      op: In
      value: [foo]
    host:
      negate: false
      op: In
      value: ["192.0.2.1"]
    operation:
      op: Eq
      value: WRITE
    resource:
      resourceType: TOPIC
      resourceName:
        negate: false
        op: In
        value: [bar]

$ java -cp kalc-cli/build/libs/kalc-cli-*.jar com.mayreh.kalc.cli.Cli \
    check --base-policy policy.yml --taget-policy target.yml --check intersection
Result  : true
Example : Optional[RequestTuple(userPrincipal="foo", host="192.0.2.1", operation=ALTER, resourceType=CLUSTER, resourceName="bar")]
```

The checker understands the semantics of wildcard (host) and `ALL` (operation) and outputs the example.

#### Check the policy doesn't allow ALTER CLUSTER from any user who is not admin

```bash
$ cat target.yml
---
entries:
- permission: Allow
  constraint:
    userPrincipal:
      negate: true
      op: In
      value: [admin]
    host:
      negate: false
      op: In
      value: ["*"]
    operation:
      op: Eq
      value: ALTER
    resource:
      resourceType: CLUSTER
      resourceName:
        negate: false
        op: In
        value: ["*"]

$ java -cp kalc-cli/build/libs/kalc-cli-*.jar com.mayreh.kalc.cli.Cli \
    check --base-policy policy.yml --taget-policy target.yml --check intersection
Result  : false
Example : Optional.empty
```

#### Check topic:bar can be READ by User:foo from any host

```bash
$ cat target.yml
---
entries:
- permission: Allow
  constraint:
    userPrincipal:
      negate: false
      op: In
      value: [foo]
    host:
      negate: false
      op: In
      value: ["*"]
    operation:
      op: Eq
      value: READ
    resource:
      resourceType: TOPIC
      resourceName:
        negate: false
        op: In
        value: [bar]

$ java -cp kalc-cli/build/libs/kalc-cli-*.jar com.mayreh.kalc.cli.Cli \
    check --base-policy policy.yml --taget-policy target.yml --check supersetOf
Result          : true
Counter Example : Optional.empty
```

The checker can evaluate if a policy allows arbitrary requests allowed by another policy.
