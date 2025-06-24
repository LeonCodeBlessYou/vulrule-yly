---
title: evdns_search_add

---


## API Overview
**evdns_search_add** is an API in **libevent**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 1 of evdns_search_add must be released by calling evdns_search_clear, with the same object passed as the 1-th argument to evdns_search_clear

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
  fc.getTarget().hasName("evdns_search_add")
  and result.asExpr() = fc.getArgument(0)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("evdns_search_clear")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("evdns_search_add")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```