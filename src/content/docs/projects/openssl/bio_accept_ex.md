---
title: bio_accept_ex

---


## API Overview
**bio_accept_ex** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

BIO_accept_ex() returns the accepted socket on success or B\<INVALID_SOCKET\> (-1) on error.  When an error has occurred, the OpenSSL error stack will hold the error data and errno has the system error.

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
    this.getTarget().hasName("BIO_accept_ex")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of BIO_accept_ex."
```