---
title: av_mdct_init

---


## API Overview
**av_mdct_init** is an API in **FFmpeg**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

The return value of av_mdct_init must be released by calling av_mdct_end, with the same object passed as the 1-th argument to av_mdct_end

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
  fc.getTarget().hasName("av_mdct_init")
  and result.asExpr() = fc
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("av_mdct_end")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("av_mdct_init")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

```