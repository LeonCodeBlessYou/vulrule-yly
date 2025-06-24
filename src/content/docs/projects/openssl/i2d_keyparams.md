---
---


## API Overview
**i2d_keyparams** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

i2d_PrivateKey(), i2d_PrivateKey_bio(), i2d_PrivateKey_fp(), i2d_PublicKey(), i2d_KeyParams() i2d_KeyParams_bio() return the number of bytes successfully encoded or a negative value if an error occurs. The error code can be obtained by calling L\<ERR_get_error(3)\>.

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
    this.getTarget().hasName("i2d_KeyParams")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of i2d_KeyParams."
```