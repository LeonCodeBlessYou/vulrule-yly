---
---


## API Overview
**ossl_cmp_ctx_reqextensions_have_san** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

OSSL_CMP_CTX_get_option(), OSSL_CMP_CTX_reqExtensions_have_SAN(), OSSL_CMP_CTX_get_status(), and OSSL_CMP_CTX_get_failInfoCode() return the intended value as described above or -1 on error.

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
    this.getTarget().hasName("OSSL_CMP_CTX_reqExtensions_have_SAN")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of OSSL_CMP_CTX_reqExtensions_have_SAN."
```