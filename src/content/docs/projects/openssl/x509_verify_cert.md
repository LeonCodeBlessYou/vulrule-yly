---
title: x509_verify_cert

---


## API Overview
**x509_verify_cert** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

Both X509_verify_cert() and X509_STORE_CTX_verify() return 1 if a complete chain can be built and validated, otherwise they return 0, and in exceptional circumstances (such as malloc failure and internal errors) they can also return a negative code.

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
    this.getTarget().hasName("X509_verify_cert")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of X509_verify_cert."
```