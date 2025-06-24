---
---


## API Overview
**av_opt_get_key_value** is an API in **FFmpeg**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 6 of av_opt_get_key_value must be released by calling av_free, with the same object passed as the 1-th argument to av_free

:::

:::info

- Tags: **api pair**
- Parameter Index: **5**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("av_opt_get_key_value")
  and result.asExpr() = fc.getArgument(5)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("av_free")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("av_opt_get_key_value")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```