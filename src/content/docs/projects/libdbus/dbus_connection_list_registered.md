---
title: dbus_connection_list_registered

---


## API Overview
**dbus_connection_list_registered** is an API in **libdbus**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 3 of dbus_connection_list_registered must be released by calling dbus_free_string_array, with the same object passed as the 1-th argument to dbus_free_string_array

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
  fc.getTarget().hasName("dbus_connection_list_registered")
  and result.asExpr() = fc.getArgument(2)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("dbus_free_string_array")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("dbus_connection_list_registered")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```