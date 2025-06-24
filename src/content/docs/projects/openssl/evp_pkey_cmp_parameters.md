---
title: evp_pkey_cmp_parameters

---


## API Overview
**evp_pkey_cmp_parameters** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

The functions EVP_PKEY_cmp_parameters(), EVP_PKEY_parameters_eq(),  EVP_PKEY_cmp() and EVP_PKEY_eq() return 1 if their inputs match, 0 if they don't match, -1 if the key types are different and -2 if the operation is not supported.

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
    this.getTarget().hasName("EVP_PKEY_cmp_parameters")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of EVP_PKEY_cmp_parameters."
```