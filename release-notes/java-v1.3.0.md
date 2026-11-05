# LumoAuth Java SDK v1.3.0 (`java-v1.3.0`)

**Release Date:** November 5, 2026  
**Tag:** `java-v1.3.0`

## Packages Updated

| Package | Version |
| :--- | :--- |
| `io.lumoauth:lumo-auth-parent` | `1.3.0` |
| `io.lumoauth:lumo-auth-java` | `1.3.0` |
| `io.lumoauth:lumo-auth-spring-boot-starter` | `1.3.0` |

---

## Improvements & Fixes

### Spring Boot Starter Annotation Processing on JDK 23+ (`io.lumoauth:lumo-auth-spring-boot-starter`)

- Configured `maven-compiler-plugin` with `<proc>full</proc>` in the parent `pom.xml` so Spring Boot annotation processors execute on JDK 23 and newer, ensuring `META-INF/spring-configuration-metadata.json` and `META-INF/spring-autoconfigure-metadata.properties` are packaged in the starter jar for IDE auto-completion of `lumoauth.*` properties and faster auto-configuration.

### Dependency & Release Train Alignment

- **Spring Boot & Test Dependencies**: Aligned the managed dependency baseline with Spring Boot `4.1.2`, Jackson `2.19.4`, JUnit `5.14.4`, and AssertJ `3.27.7`.
- **v1.3.0 Release Train**: Bumped `io.lumoauth:lumo-auth-parent`, `io.lumoauth:lumo-auth-java`, and `io.lumoauth:lumo-auth-spring-boot-starter` to `1.3.0` (`Version.SDK` stamped from POM) and dated the `1.3.0` section in `CHANGELOG.md`.

---

## Commit Log (`java-v1.2.0..java-v1.3.0`)

- `fc0d55c` — `release: lumo-auth-java@1.3.0`
- `dbcdf1f` — `docs: update CHANGELOG with fixes and changes for Spring Boot starter on JDK 23+`
