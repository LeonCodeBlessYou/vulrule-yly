---
---


## API Overview
**evp_pkey_get_default_digest_name** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

EVP_PKEY_get_default_digest_name() and EVP_PKEY_get_default_digest_nid() both return 1 if the message digest is advisory (that is other digests can be used) and 2 if it is mandatory (other digests can not be used). They return 0 or a negative value for failure.  In particular a return value of -2 indicates the operation is not supported by the public key algorithm.

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
    this.getTarget().hasName("EVP_PKEY_get_default_digest_name")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of EVP_PKEY_get_default_digest_name."
```