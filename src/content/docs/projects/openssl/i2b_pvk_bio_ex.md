---
title: i2b_pvk_bio_ex

---


## API Overview
**i2b_pvk_bio_ex** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

i2b_PVK_bio() and i2b_PVK_bio_ex() return the number of bytes successfully encoded or a negative value if an error occurs. The error code can be obtained by calling L\<ERR_get_error(3)\>.

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
    this.getTarget().hasName("i2b_PVK_bio_ex")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of i2b_PVK_bio_ex."
```