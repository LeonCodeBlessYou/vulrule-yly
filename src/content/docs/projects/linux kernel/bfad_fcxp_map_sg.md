---
title: bfad_fcxp_map_sg

---


## API Overview
**bfad_fcxp_map_sg** is an API in **Linux kernel**. This rule belongs to the **api pair** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

The resource acquired by bfad_fcxp_map_sg must be properly released using bfad_fcxp_free_mem

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
  fc.getTarget().hasName("bfad_fcxp_map_sg")
  and result.asExpr() = fc
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("bfad_fcxp_free_mem")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("bfad_fcxp_map_sg")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

    
```