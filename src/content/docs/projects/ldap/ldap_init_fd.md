---
title: ldap_init_fd

---


## API Overview
**ldap_init_fd** is an API in **ldap**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 4 of ldap_init_fd must be released by calling ldap_unbind, with the same object passed as the 1-th argument to ldap_unbind

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
  fc.getTarget().hasName("ldap_init_fd")
  and result.asExpr() = fc.getArgument(3)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("ldap_unbind")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("ldap_init_fd")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```