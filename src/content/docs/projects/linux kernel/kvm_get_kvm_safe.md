---
title: kvm_get_kvm_safe

---


## API Overview
**kvm_get_kvm_safe** is an API in **Linux kernel**. This rule belongs to the **api pair** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

The resource acquired by kvm_get_kvm_safe must be properly released using kvm_put_kvm

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
  fc.getTarget().hasName("kvm_get_kvm_safe")
  and result.asExpr() = fc.getArgument(0)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("kvm_put_kvm")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("kvm_get_kvm_safe")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

    
```