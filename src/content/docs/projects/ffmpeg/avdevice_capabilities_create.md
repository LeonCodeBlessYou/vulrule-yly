---
title: avdevice_capabilities_create

---


## API Overview
**avdevice_capabilities_create** is an API in **ffmpeg**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 3 of avdevice_capabilities_create must be released by calling av_dict_free, with the same object passed as the 1-th argument to av_dict_free

:::

:::info

- Tags: **api pair**
- Parameter Index: **2**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("avdevice_capabilities_create")
  and result.asExpr() = fc.getArgument(2)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("av_dict_free")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("avdevice_capabilities_create")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```