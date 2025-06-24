---
title: ldap_get_values_len

---


## API Overview
**ldap_get_values_len** is an API in **ldap**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

The return value of ldap_get_values_len must be released by calling ldap_value_free_len, with the same object passed as the 1-th argument to ldap_value_free_len

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
  fc.getTarget().hasName("ldap_get_values_len")
  and result.asExpr() = fc
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("ldap_value_free_len")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("ldap_get_values_len")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

```