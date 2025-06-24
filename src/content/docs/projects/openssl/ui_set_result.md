---
title: ui_set_result

---


## API Overview
**ui_set_result** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

UI_set_result() returns 0 on success or when the UI string is of any type other than B\<UIT_PROMPT\>, B\<UIT_VERIFY\> or B\<UIT_BOOLEAN\>, -1 on error.

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
    this.getTarget().hasName("UI_set_result")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of UI_set_result."
```