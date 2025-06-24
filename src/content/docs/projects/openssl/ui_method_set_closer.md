---
---


## API Overview
**ui_method_set_closer** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

UI_method_set_opener(), UI_method_set_writer(), UI_method_set_flusher(), UI_method_set_reader(), UI_method_set_closer(), UI_method_set_data_duplicator() and UI_method_set_prompt_constructor() return 0 on success, -1 if the given B\<method\> is NULL.

:::

:::info

- Tags: **return value check**
- Parameter Index: **N/A**
- CWE Type: **CWE-253**

:::

## Rule Code
```python
import cpp

class OpenSSLFunctionCall extends FunctionCall {
  OpenSSLFunctionCall() {
    this.getTarget().hasName("UI_method_set_closer")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of UI_method_set_closer."
```