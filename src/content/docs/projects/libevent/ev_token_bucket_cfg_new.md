---
title: ev_token_bucket_cfg_new

---


## API Overview
**ev_token_bucket_cfg_new** is an API in **libevent**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

The return value of ev_token_bucket_cfg_new must be released by calling ev_token_bucket_cfg_free, with the same object passed as the 1-th argument to ev_token_bucket_cfg_free

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
  fc.getTarget().hasName("ev_token_bucket_cfg_new")
  and result.asExpr() = fc
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("ev_token_bucket_cfg_free")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("ev_token_bucket_cfg_new")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

```