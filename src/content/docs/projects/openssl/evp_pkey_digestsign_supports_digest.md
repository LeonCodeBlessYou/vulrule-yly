---
---


## API Overview
**evp_pkey_digestsign_supports_digest** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

The EVP_PKEY_digestsign_supports_digest() function returns 1 if the message digest algorithm identified by I\<name\> can be used for public key signature operations associated with key I\<pkey\> and 0 if it cannot be used. It returns a negative value for failure.

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
    this.getTarget().hasName("EVP_PKEY_digestsign_supports_digest")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of EVP_PKEY_digestsign_supports_digest."
```