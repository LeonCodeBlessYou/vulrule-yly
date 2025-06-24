---
title: x509_req_verify_ex

---


## API Overview
**x509_req_verify_ex** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

X509_verify(), X509_REQ_verify_ex(), X509_REQ_verify() and X509_CRL_verify() return 1 if the signature is valid and 0 if the signature check fails. If the signature could not be checked at all because it was ill-formed, the certificate or the request was not complete or some other error occurred then -1 is returned.

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
    this.getTarget().hasName("X509_REQ_verify_ex")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of X509_REQ_verify_ex."
```