---
title: x509_lookup_ctrl

---


## API Overview
**x509_lookup_ctrl** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

X509_LOOKUP_ctrl() returns -1 if the B\<X509_LOOKUP\> doesn't have an associated B\<X509_LOOKUP_METHOD\>, or 1 if the X\<509_LOOKUP_METHOD\> doesn't have a control function. Otherwise, it returns what the control function in the B\<X509_LOOKUP_METHOD\> returns, which is usually 1 on success and 0 in error.

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
    this.getTarget().hasName("X509_LOOKUP_ctrl")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of X509_LOOKUP_ctrl."
```