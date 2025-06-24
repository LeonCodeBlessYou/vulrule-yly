---
title: gnutls_srp_allocate_server_credentials

---


## API Overview
**gnutls_srp_allocate_server_credentials** is an API in **libgnutls**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 1 of gnutls_srp_allocate_server_credentials must be released by calling gnutls_srp_free_server_credentials, with the same object passed as the 1-th argument to gnutls_srp_free_server_credentials

:::

:::info

- Tags: **api pair**
- Parameter Index: **0**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("gnutls_srp_allocate_server_credentials")
  and result.asExpr() = fc.getArgument(0)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("gnutls_srp_free_server_credentials")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("gnutls_srp_allocate_server_credentials")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```