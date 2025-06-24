---
---


## API Overview
**av_fast_padded_mallocz** is an API in **FFmpeg**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 2 of av_fast_padded_mallocz must be released by calling av_freep, with the same object passed as the 2-th argument to av_freep

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
  fc.getTarget().hasName("av_fast_padded_mallocz")
  and result.asExpr() = fc.getArgument(1)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("av_freep")
  and result.asExpr() = fc.getArgument(1)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("av_fast_padded_mallocz")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```