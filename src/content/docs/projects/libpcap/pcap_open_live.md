---
title: pcap_open_live

---


## API Overview
**pcap_open_live** is an API in **libpcap**. This rule belongs to the **param-value** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

you should use a non-zero timeout
https://www.tcpdump.org/pcap.html

:::

:::info

- Tags: **param-value**
- Parameter Index: **N/A**
- CWE Type: **N/A**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.customs.non_zero
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.security.Security
import DataFlow::PathGraph
class TestConfiguration extends TaintTracking::Configuration {
  TestConfiguration() { this = "TestConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists( | source.asExpr().isConstant())
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      fc.getTarget().hasName("pcap_open_live")
      and fc.getArgument(3) = sink.asExpr()
    )
  }
}
from FunctionCall fc, TestConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where fc.getTarget().hasQualifiedName("pcap_open_live")
    and cfg.hasFlowPath(source, sink)
    and source.toString().toFloat() != non_zero()
select sink.getNode().getLocation()
```