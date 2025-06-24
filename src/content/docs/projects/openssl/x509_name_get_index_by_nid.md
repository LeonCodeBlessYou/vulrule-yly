---
title: x509_name_get_index_by_nid

---


## API Overview
**x509_name_get_index_by_nid** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

X509_NAME_get_index_by_NID() and X509_NAME_get_index_by_OBJ() return the index of the next matching entry or -1 if not found. X509_NAME_get_index_by_NID() can also return -2 if the supplied NID is invalid.

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
    this.getTarget().hasName("X509_NAME_get_index_by_NID")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of X509_NAME_get_index_by_NID."
```