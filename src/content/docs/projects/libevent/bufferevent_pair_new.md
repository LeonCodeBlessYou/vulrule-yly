---
---


## API Overview
**bufferevent_pair_new** is an API in **libevent**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 3 of bufferevent_pair_new must be released by calling bufferevent_free, with the same object passed as the 1-th argument to bufferevent_free

:::

:::info

- Tags: **api pair**
- Parameter Index: **2**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("bufferevent_pair_new")
  and result.asExpr() = fc.getArgument(2)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("bufferevent_free")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("bufferevent_pair_new")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```