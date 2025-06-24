---
title: evrpc_send_request_generic

---


## API Overview
**evrpc_send_request_generic** is an API in **libevent**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 1 of evrpc_send_request_generic must be released by calling evrpc_pool_free, with the same object passed as the 1-th argument to evrpc_pool_free

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
  fc.getTarget().hasName("evrpc_send_request_generic")
  and result.asExpr() = fc.getArgument(0)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("evrpc_pool_free")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("evrpc_send_request_generic")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```