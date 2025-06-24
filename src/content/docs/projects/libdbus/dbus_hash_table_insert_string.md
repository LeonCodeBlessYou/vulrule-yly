---
title: dbus_hash_table_insert_string

---


## API Overview
**dbus_hash_table_insert_string** is an API in **libdbus**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 3 of _dbus_hash_table_insert_string must be released by calling _dbus_mem_pool_dealloc, with the same object passed as the 2-th argument to _dbus_mem_pool_dealloc

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
  fc.getTarget().hasName("_dbus_hash_table_insert_string")
  and result.asExpr() = fc.getArgument(2)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("_dbus_mem_pool_dealloc")
  and result.asExpr() = fc.getArgument(1)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("_dbus_hash_table_insert_string")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```