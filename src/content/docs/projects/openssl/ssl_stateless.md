---
title: ssl_stateless

---


## API Overview
**ssl_stateless** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

For SSL_stateless() a return value of 1 indicates success and the B\<ssl\> object will be set up ready to continue the handshake. A return value of 0 or -1 indicates failure. If the value is 0 then a HelloRetryRequest was sent. A value of -1 indicates any other error. User code may retry the SSL_stateless() call.

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
    this.getTarget().hasName("SSL_stateless")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of SSL_stateless."
```