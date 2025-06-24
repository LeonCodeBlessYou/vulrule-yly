---
title: rcar_fcp_get

---


## API Overview
**rcar_fcp_get** is an API in **Linux kernel**. This rule belongs to the **api pair** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

The resource acquired by rcar_fcp_get must be properly released using rcar_fcp_put

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
  fc.getTarget().hasName("rcar_fcp_get")
  and result.asExpr() = fc
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("rcar_fcp_put")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("rcar_fcp_get")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

    
```