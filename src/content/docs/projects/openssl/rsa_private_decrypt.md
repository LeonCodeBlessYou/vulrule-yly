---
---


## API Overview
**rsa_private_decrypt** is an API in **openssl**. This rule belongs to the **param-value** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip



:::

:::info

- Tags: **param-value**
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
    exists(FunctionCall fc |source.asExpr() = fc and fc.getTarget().getName().matches("%alloc%"))
    or source.asExpr().getType() instanceof ArrayType
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      fc.getTarget().hasName("RSA_private_decrypt")
      and fc.getArgument(2) = sink.asExpr()
    )
  }
}
from TestConfiguration cfg, FunctionCall fc
where fc.getTarget().hasName("RSA_private_decrypt")
  and not exists(DataFlow::PathNode source, DataFlow::PathNode sink, FunctionCall fc2|
      cfg.hasFlowPath(source, sink)
      //RSA_size(host_pkey->pkey.rsa)
      and fc2.getTarget().hasName("RSA_size")
      and fc2.getArgument(0) = fc.getArgument(3)
      //RSA_private_decrypt(, RSA_size(), )
      and source.getNode().asExpr() = fc2
  )
select fc.getLocation()
```