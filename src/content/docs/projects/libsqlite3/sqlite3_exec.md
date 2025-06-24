---
---


## API Overview
**sqlite3_exec** is an API in **libsqlite3**. This rule belongs to the **mem leakage** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

To avoid memory leaks, the application should invoke sqlite3_free() on error message strings returned through the 5th parameter of sqlite3_exec() after the error message string is no longer needed.

:::

:::info

- Tags: **mem leakage**
- Parameter Index: **N/A**
- CWE Type: **CWE-772**

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
    exists(FunctionCall fc, MacroInvocation mi |
      (fc.getTarget().hasQualifiedName("sqlite3_exec") or (
          mi.getMacroName() = "sqlite3_exec"
          and fc.getTarget().hasName(mi.getMacro().getBody())
         )
      )
      and ((fc.getArgument( 5-1) = source.asDefiningArgument() and  5-1 >= 0) or
        (fc = source.asExpr() and  5-1 = -1)
      )
    )
  }
override predicate isSink(DataFlow::Node sink) {
  exists(FunctionCall fc, MacroInvocation mi |
      (fc.getTarget().hasName("sqlite3_free") or (
        mi.getMacroName() = "sqlite3_free"
        and fc.getTarget().hasName(mi.getMacro().getBody())
       )
      )
      and fc.getAnArgument() = sink.asExpr()
    )
  }
}
from TestConfiguration cfg, FunctionCall fc, MacroInvocation mi
where (fc.getTarget().hasQualifiedName("sqlite3_exec") or (
          mi.getMacroName() = "sqlite3_exec"
          and fc.getTarget().hasName(mi.getMacro().getBody())
         )
      )
      and not exists(DataFlow::PathNode source, DataFlow::PathNode sink|cfg.hasFlowPath(source, sink) and
        ((fc.getArgument( 5-1) = source.getNode().asDefiningArgument() and  5-1 >= 0) or
          (fc = source.getNode().asExpr() and  5-1 = -1)
        )
      )
      and not (fc.getArgument( 5-1).isConstant() and  5-1>=0)
select fc.getLocation()
```