---
---


## API Overview
**ui_get_result_minsize** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

UI_get_result_minsize() returns the minimum allowed result size for the UI string for B\<UIT_PROMPT\> and B\<UIT_VERIFY\> type strings, -1 for any other type.

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
    this.getTarget().hasName("UI_get_result_minsize")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of UI_get_result_minsize."
```