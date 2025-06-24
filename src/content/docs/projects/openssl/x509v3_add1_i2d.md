---
title: x509v3_add1_i2d

---


## API Overview
**x509v3_add1_i2d** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

X509V3_add1_i2d() returns 1 if the operation is successful and 0 if it fails due to a non-fatal error (extension not found, already exists, cannot be encoded) or -1 due to a fatal error such as a memory allocation failure.

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
    this.getTarget().hasName("X509V3_add1_i2d")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of X509V3_add1_i2d."
```