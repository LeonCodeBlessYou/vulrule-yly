---
title: x509v3_get_ext_by_obj

---


## API Overview
**x509v3_get_ext_by_obj** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

X509v3_get_ext_by_NID() X509v3_get_ext_by_OBJ() and X509v3_get_ext_by_critical() return the an extension index or B\<-1\> if an error occurs.

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
    this.getTarget().hasName("X509v3_get_ext_by_OBJ")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of X509v3_get_ext_by_OBJ."
```