---
title: zpci_bus_get

---


## API Overview
**zpci_bus_get** is an API in **Linux kernel**. This rule belongs to the **api pair** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

The resource acquired by zpci_bus_get must be properly released using zpci_bus_put

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
  fc.getTarget().hasName("zpci_bus_get")
  and result.asExpr() = fc
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("zpci_bus_put")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("zpci_bus_get")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

    
```