---
title: ossl_cmp_try_certreq

---


## API Overview
**ossl_cmp_try_certreq** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

OSSL_CMP_try_certreq() returns 1 if the requested certificate is available via L\<OSSL_CMP_CTX_get0_newCert(3)\> or on successfully aborting a pending certificate request, 0 on error, and -1 in case a 'waiting' status has been received and checkAfter value is available. In the latter case L\<OSSL_CMP_CTX_get0_newCert(3)\> yields NULL and the output parameter I\<checkAfter\> has been used to assign the received value unless I\<checkAfter\> is NULL.

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
    this.getTarget().hasName("OSSL_CMP_try_certreq")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of OSSL_CMP_try_certreq."
```