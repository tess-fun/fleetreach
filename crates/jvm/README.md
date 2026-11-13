# fleetreach-jvm

[![crates.io](https://img.shields.io/crates/v/fleetreach-jvm.svg)](https://crates.io/crates/fleetreach-jvm)
[![docs.rs](https://img.shields.io/docsrs/fleetreach-jvm)](https://docs.rs/fleetreach-jvm)
[![CI](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml/badge.svg)](https://github.com/tess-fun/fleetreach/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/fleetreach-jvm.svg)](#license)

<!-- Generated from `src/lib.rs` doc comments by cargo-rdme. Do not edit by hand; run `cargo rdme`. -->
<!-- cargo-rdme start -->

JVM call graphs (spec 16, row 13): which sink methods can a service reach?

Jars and class files are data: they are unzipped and parsed, never loaded or run.

`classpath::load` reads a service's classes, from plain jars or from the nested layout of
Spring Boot fat jars and wars. `graph::analyze` then walks a rapid type analysis call
graph from the service's entry points, and `verdict::judge` turns that into an answer
for one curated sink record. `fleetreach scan --reachability=jvm` runs this over each
container image's Java archives.

The graph over-approximates on purpose. Every non-private method of the service's own
classes is an entry point, so a framework this crate has never heard of cannot hide app
code. Library code a framework calls by name comes in through what names it:

- annotations (Spring, JAX-RS, servlet, CDI, JSF, and any annotation meta-annotated with
  one of them), with what their elements name, through annotations on annotations;
- any class named in a jar's XML, properties or `META-INF/services` files, which one rule
  covers: `web.xml`, `faces-config.xml`, `spring.factories`, `AutoConfiguration.imports`,
  Spring XML, Struts plugins, Camel component files;
- strings and class constants in reached code that name a class;
- generated classes loaded by a built name (JBoss Logging, Undertow's parser).

A virtual call lands only on classes something made, by `new` or by one of those routes, and
on the type the call is written against. Code outside the graph still reaches an instance:
the JDK and proxies call what its outside types declare, and frameworks call its property
accessors, `hashCode`, `equals` and `toString`.

What still escapes is counted where it can be: `graph::Analysis::open_reflection` lists
reached call sites that take a class or method name no constant gives. So "not reached"
always means "not reached in this graph", and `verdict::judge` says so with those limits.
Run on five real Spring services, at most 0.05% of the methods the JVM ran were outside the
graph, in three kinds this crate does not model: template expressions (`#numbers` in
Thymeleaf), class names built at run time, and a few reflective calls by method name. The
newer class files of multi-release jars are not read either.

<!-- cargo-rdme end -->

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../../LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
