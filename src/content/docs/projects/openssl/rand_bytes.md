---
title: rand_bytes

---


## API Overview
**rand_bytes** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

RAND_bytes() and RAND_priv_bytes() return 1 on success, -1 if not supported by the current RAND method, or 0 on other failure. The error code can be obtained by L\<ERR_get_error(3)\>.

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
    this.getTarget().hasName("RAND_bytes")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of RAND_bytes."
```