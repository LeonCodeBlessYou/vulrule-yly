---
title: i2d_ossl_cmp_msg_bio

---


## API Overview
**i2d_ossl_cmp_msg_bio** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

OSSL_CMP_MSG_write() and i2d_OSSL_CMP_MSG_bio() return the number of bytes successfully encoded or a negative value if an error occurs.

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
    this.getTarget().hasName("i2d_OSSL_CMP_MSG_bio")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of i2d_OSSL_CMP_MSG_bio."
```