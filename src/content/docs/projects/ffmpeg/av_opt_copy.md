---
title: av_opt_copy

---


## API Overview
**av_opt_copy** is an API in **FFmpeg**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 2 of av_opt_copy must be released by calling av_opt_free, with the same object passed as the 1-th argument to av_opt_free

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
  fc.getTarget().hasName("av_opt_copy")
  and result.asExpr() = fc.getArgument(1)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("av_opt_free")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("av_opt_copy")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```