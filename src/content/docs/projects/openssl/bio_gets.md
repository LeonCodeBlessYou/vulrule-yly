---
title: bio_gets

---


## API Overview
**bio_gets** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

BIO_gets() returns -2 if the "gets" operation is not implemented by the BIO or -1 on other errors. Otherwise it typically returns the amount of data read, but depending on the implementation it may return only the length up to the first NUL character contained in the data read. In any case the trailing NUL that is added after the data read is not included in the length returned.

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
    this.getTarget().hasName("BIO_gets")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of BIO_gets."
```