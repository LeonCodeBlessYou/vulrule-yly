---
title: evp_verifyfinal_ex

---


## API Overview
**evp_verifyfinal_ex** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

EVP_VerifyFinal_ex() and EVP_VerifyFinal() return 1 for a correct signature, 0 for failure and -1 if some other error occurred.

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
    this.getTarget().hasName("EVP_VerifyFinal_ex")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of EVP_VerifyFinal_ex."
```