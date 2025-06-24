---
---


## API Overview
**pcap_list_tstamp_types** is an API in **libpcap**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 2 of pcap_list_tstamp_types must be released by calling pcap_free_datalinks, with the same object passed as the 1-th argument to pcap_free_datalinks

:::

:::info

- Tags: **api pair**
- Parameter Index: **1**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("pcap_list_tstamp_types")
  and result.asExpr() = fc.getArgument(1)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("pcap_free_datalinks")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("pcap_list_tstamp_types")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```