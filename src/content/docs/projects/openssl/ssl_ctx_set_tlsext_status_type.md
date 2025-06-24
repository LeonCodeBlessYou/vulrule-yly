---
---


## API Overview
**ssl_ctx_set_tlsext_status_type** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

SSL_CTX_get_tlsext_status_type() returns the value previously set by SSL_CTX_set_tlsext_status_type(), or -1 if not set.

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
    this.getTarget().hasName("SSL_CTX_set_tlsext_status_type")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of SSL_CTX_set_tlsext_status_type."
```