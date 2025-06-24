---
title: evp_pkey_paramgen_init

---


## API Overview
**evp_pkey_paramgen_init** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

EVP_PKEY_keygen_init(), EVP_PKEY_paramgen_init(), EVP_PKEY_keygen() and EVP_PKEY_paramgen() return 1 for success and 0 or a negative value for failure. In particular a return value of -2 indicates the operation is not supported by the public key algorithm.

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
    this.getTarget().hasName("EVP_PKEY_paramgen_init")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of EVP_PKEY_paramgen_init."
```