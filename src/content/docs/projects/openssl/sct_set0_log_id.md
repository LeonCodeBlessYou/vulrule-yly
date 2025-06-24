---
title: sct_set0_log_id

---


## API Overview
**sct_set0_log_id** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

SCT_set0_log_id() and B\<SCT_set1_log_id\> return 1 if the specified LogID is a valid SHA-256 hash, 0 otherwise. Additionally, B\<SCT_set1_log_id\> returns 0 if malloc fails.

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
    this.getTarget().hasName("SCT_set0_log_id")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of SCT_set0_log_id."
```