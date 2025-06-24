---
title: evdns_base_resolve_reverse_ipv6

---


## API Overview
**evdns_base_resolve_reverse_ipv6** is an API in **libevent**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

The return value of evdns_base_resolve_reverse_ipv6 must be released by calling evdns_cancel_request, with the same object passed as the 1-th argument to evdns_cancel_request

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
  fc.getTarget().hasName("evdns_base_resolve_reverse_ipv6")
  and result.asExpr() = fc
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("evdns_cancel_request")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("evdns_base_resolve_reverse_ipv6")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

```