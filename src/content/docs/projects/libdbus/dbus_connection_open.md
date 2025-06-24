---
title: dbus_connection_open

---


## API Overview
**dbus_connection_open** is an API in **libdbus**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 1 of dbus_connection_open must be released by calling dbus_bus_request_name, with the same object passed as the 2-th argument to dbus_bus_request_name

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
  fc.getTarget().hasName("dbus_connection_open")
  and result.asExpr() = fc.getArgument(0)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("dbus_bus_request_name")
  and result.asExpr() = fc.getArgument(1)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("dbus_connection_open")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```