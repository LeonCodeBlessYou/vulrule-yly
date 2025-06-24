---
---


## API Overview
**ldap_sasl_bind_s** is an API in **Ldap**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 7 of ldap_sasl_bind_s must be released by calling ber_bvfree, with the same object passed as the 2-th argument to ber_bvfree

:::

:::info

- Tags: **api pair**
- Parameter Index: **6**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("ldap_sasl_bind_s")
  and result.asExpr() = fc.getArgument(6)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("ber_bvfree")
  and result.asExpr() = fc.getArgument(1)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("ldap_sasl_bind_s")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```