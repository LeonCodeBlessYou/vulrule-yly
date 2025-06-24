---
title: ati_remote_alloc_buffers

---


## API Overview
**ati_remote_alloc_buffers** is an API in **Linux kernel**. This rule belongs to the **api pair** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

The resource acquired by ati_remote_alloc_buffers must be properly released using ati_remote_free_buffers

:::

:::info

- Tags: **api pair**
- Parameter Index: **N/A**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("ati_remote_alloc_buffers")
  and result.asExpr() = fc.getArgument(0)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("ati_remote_free_buffers")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("ati_remote_alloc_buffers")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

    
```