---
title: ossl_ess_check_signing_certs

---


## API Overview
**ossl_ess_check_signing_certs** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

OSSL_ESS_check_signing_certs() returns 1 on success, 0 if a required certificate cannot be found, -1 on other error.

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
    this.getTarget().hasName("OSSL_ESS_check_signing_certs")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of OSSL_ESS_check_signing_certs."
```