---
---


## API Overview
**ocsp_check_nonce** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

OCSP_check_nonce() returns the result of the nonce comparison between B\<req\> and B\<resp\>. The return value indicates the result of the comparison.  If nonces are present and equal 1 is returned. If the nonces are absent 2 is returned. If a nonce is present in the response only 3 is returned. If nonces are present and unequal 0 is returned. If the nonce is present in the request only then -1 is returned.

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
    this.getTarget().hasName("OCSP_check_nonce")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of OCSP_check_nonce."
```