---
title: rsa_check_key_ex

---


## API Overview
**rsa_check_key_ex** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

RSA_check_key_ex() and RSA_check_key() return 1 if B\<rsa\> is a valid RSA key, and 0 otherwise. They return -1 if an error occurs while checking the key.

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
    this.getTarget().hasName("RSA_check_key_ex")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of RSA_check_key_ex."
```