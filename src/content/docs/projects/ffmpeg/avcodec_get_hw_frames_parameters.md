---
---


## API Overview
**avcodec_get_hw_frames_parameters** is an API in **ffmpeg**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 4 of avcodec_get_hw_frames_parameters must be released by calling av_buffer_unref, with the same object passed as the 1-th argument to av_buffer_unref

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
  fc.getTarget().hasName("avcodec_get_hw_frames_parameters")
  and result.asExpr() = fc.getArgument(3)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("av_buffer_unref")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("avcodec_get_hw_frames_parameters")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```