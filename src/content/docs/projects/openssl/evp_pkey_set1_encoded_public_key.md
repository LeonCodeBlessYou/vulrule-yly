---
title: evp_pkey_set1_encoded_public_key

---


## API Overview
**evp_pkey_set1_encoded_public_key** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

EVP_PKEY_set1_encoded_public_key() returns 1 for success and 0 or a negative value for failure.

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
    this.getTarget().hasName("EVP_PKEY_set1_encoded_public_key")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of EVP_PKEY_set1_encoded_public_key."
```