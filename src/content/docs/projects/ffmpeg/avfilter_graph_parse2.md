---
---


## API Overview
**avfilter_graph_parse2** is an API in **FFmpeg**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 4 of avfilter_graph_parse2 must be released by calling avfilter_inout_free, with the same object passed as the 1-th argument to avfilter_inout_free

:::

:::info

- Tags: **api pair**
- Parameter Index: **3**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("avfilter_graph_parse2")
  and result.asExpr() = fc.getArgument(3)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("avfilter_inout_free")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("avfilter_graph_parse2")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```