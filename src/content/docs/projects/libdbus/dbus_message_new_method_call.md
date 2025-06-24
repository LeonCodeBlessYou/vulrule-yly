---
---


## API Overview
**dbus_message_new_method_call** is an API in **libdbus**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Parameter 4 of dbus_message_new_method_call must be released by calling dbus_bus_request_name, with the same object passed as the 2-th argument to dbus_bus_request_name

:::

:::info

- Tags: **api pair**
- Parameter Index: **3**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("dbus_message_new_method_call")
  and result.asExpr() = fc.getArgument(3)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("dbus_bus_request_name")
  and result.asExpr() = fc.getArgument(1)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("dbus_message_new_method_call")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()
```