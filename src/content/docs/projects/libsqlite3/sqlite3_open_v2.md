---
---


## API Overview
**sqlite3_open_v2** is an API in **libsqlite3**. This rule belongs to the **mem leakage** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

Whether or not an error occurs when it is opened, resources associated with the database connection handle should be released by passing it to sqlite3_close() when it is no longer required.
https://www.sqlite.org/c3ref/open.html

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
    exists(FunctionCall fc |
      fc.getTarget().hasName("sqlite3_open_v2")
      and ( (fc.getArgument(1) = source.asDefiningArgument() and 1 >= 0) or
            (fc = source.asExpr() and 1 = -1)
          )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      fc.getTarget().hasName("sqlite3_close")
      and fc.getAnArgument() = sink.asExpr()
    )
  }
}
from TestConfiguration cfg, FunctionCall fc
where fc.getTarget().hasName("sqlite3_open_v2")
      and not exists(DataFlow::PathNode source, DataFlow::PathNode sink|cfg.hasFlowPath(source, sink) and (
           (fc.getArgument(1) = source.getNode().asDefiningArgument() and 1 >= 0) or
           (fc = source.getNode().asExpr() and 1 = -1)
        )
      )
select fc.getLocation()
```