---
---


## API Overview
**dbus_message_iter_get_array_len** is an API in **libdbus**. This rule belongs to the **deprecated API** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

This function is deprecated on the grounds that it is stupid.

:::

:::info

- Tags: **deprecated API**
- Parameter Index: **N/A**
- CWE Type: **CWE-477**

:::

## Rule Code
```python
import semmle.code.cpp.dataflow.DataFlow

from FunctionCall fc
where fc.getTarget().hasQualifiedName("dbus_message_iter_get_array_len")
select fc.getLocation()
```