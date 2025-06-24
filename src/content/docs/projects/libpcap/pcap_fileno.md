---
---


## API Overview
**pcap_fileno** is an API in **libpcap**. This rule belongs to the **return value check** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

If p refers to a ``savefile'' that was opened using functions such as pcap_open_offline(3PCAP) or pcap_fopen_offline(3PCAP), a ``dead'' pcap_t opened using pcap_open_dead(3PCAP), or a pcap_t that was created with pcap_create() but that has not yet been activated with pcap_activate(), it returns PCAP_ERROR. https://www.tcpdump.org/manpages/pcap_fileno.3pcap.html
The fstat() function shall obtain information about an open file associated with the file descriptor fildes, and shall write it to the area pointed to by buf.http://man7.org/linux/man-pages/man3/fstat.3p.html
pcap_fileno对pcap_open_offline创建的savefile会返回error，没有检查就作为另一个api的输入

:::

:::info

- Tags: **return value check**
- Parameter Index: **N/A**
- CWE Type: **CWE-253**

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
    exists(FunctionCall fc |
      fc.getTarget().hasName("pcap_fileno")
      and fc = source.asExpr()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(| sink.asExpr().getEnclosingStmt() instanceof IfStmt)
  }
}

from FunctionCall fc, TestConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink

where fc.getTarget().hasQualifiedName("pcap_fileno")
    and not exists(|cfg.hasFlowPath(source, sink) and source.getNode().asExpr() = fc)
select fc.getLocation()
```