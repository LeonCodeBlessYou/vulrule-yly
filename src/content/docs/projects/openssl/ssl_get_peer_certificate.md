---
title: ssl_get_peer_certificate

---


## API Overview
**ssl_get_peer_certificate** is an API in **openssl**. This rule belongs to the **unfreed object** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

The X509 object must be explicitly freed using X509_free().

:::

:::info

- Tags: **unfreed object**
- Parameter Index: **N/A**
- CWE Type: **N/A**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.security.Security
import DataFlow::PathGraph
class TestConfiguration extends TaintTracking::Configuration {
  TestConfiguration() { this = "TestConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists(FunctionCall fc |
      fc.getTarget().hasName("SSL_get_peer_certificate")
      and ( (fc.getArgument(-1) = source.asDefiningArgument() and -1 >= 0) or
            (fc = source.asExpr() and -1 = -1)
          )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      fc.getTarget().hasName("X509_free")
      and fc.getAnArgument() = sink.asExpr()
    )
  }
}
from TestConfiguration cfg, FunctionCall fc
where fc.getTarget().hasName("SSL_get_peer_certificate")
      and not exists(DataFlow::PathNode source, DataFlow::PathNode sink|cfg.hasFlowPath(source, sink) and (
           (fc.getArgument(-1) = source.getNode().asDefiningArgument() and -1 >= 0) or
           (fc = source.getNode().asExpr() and -1 = -1)
        )
      )
select fc.getLocation()
```