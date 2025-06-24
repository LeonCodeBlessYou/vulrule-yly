---
title: av_audio_fifo_alloc

---


## API Overview
**av_audio_fifo_alloc** is an API in **ffmpeg**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

The return value of av_audio_fifo_alloc must be released by calling av_audio_fifo_free, with the same object passed as the 1-th argument to av_audio_fifo_free

:::

:::info

- Tags: **api pair**
- Parameter Index: **-1**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("av_audio_fifo_alloc")
  and result.asExpr() = fc
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("av_audio_fifo_free")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("av_audio_fifo_alloc")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

```