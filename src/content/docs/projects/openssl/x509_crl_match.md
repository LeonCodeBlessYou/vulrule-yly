---
---


## API Overview
**x509_crl_match** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

X509_NAME_cmp(), X509_issuer_and_serial_cmp(), X509_issuer_name_cmp(), X509_subject_name_cmp(), X509_CRL_cmp(), and X509_CRL_match() may return B\<-2\> to indicate an error.

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
    this.getTarget().hasName("X509_CRL_match")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of X509_CRL_match."
```