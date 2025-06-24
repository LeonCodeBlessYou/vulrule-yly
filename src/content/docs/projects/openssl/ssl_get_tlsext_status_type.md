---
---


## API Overview
**ssl_get_tlsext_status_type** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

SSL_get_tlsext_status_type() returns B\<TLSEXT_STATUSTYPE_ocsp\> on the client side if SSL_set_tlsext_status_type() was previously called, or on the server side if the client requested OCSP stapling. Otherwise -1 is returned.

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
    this.getTarget().hasName("SSL_get_tlsext_status_type")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of SSL_get_tlsext_status_type."
```