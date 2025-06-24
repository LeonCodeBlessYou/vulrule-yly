---
title: ql_alloc_buffer_queues

---


## API Overview
**ql_alloc_buffer_queues** is an API in **Linux kernel**. This rule belongs to the **api pair** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

The resource acquired by ql_alloc_buffer_queues must be properly released using ql_free_buffer_queues

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
  fc.getTarget().hasName("ql_alloc_buffer_queues")
  and result.asExpr() = fc.getArgument(0)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("ql_free_buffer_queues")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("ql_alloc_buffer_queues")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

    
```