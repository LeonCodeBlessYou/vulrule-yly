---
---


## API Overview
**evp_cipher** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

EVP_Cipher() returns the amount of encrypted / decrypted bytes, or -1 on failure if the flag B\<EVP_CIPH_FLAG_CUSTOM_CIPHER\> is set for the cipher.  EVP_Cipher() returns 1 on success or 0 on failure, if the flag B\<EVP_CIPH_FLAG_CUSTOM_CIPHER\> is not set for the cipher.

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
    this.getTarget().hasName("EVP_Cipher")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of EVP_Cipher."
```