---
---


## API Overview
**ossl_http_req_ctx_nbio** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

OSSL_HTTP_REQ_CTX_nbio() and OSSL_HTTP_REQ_CTX_nbio_d2i() return 1 for success, 0 on error or redirection, -1 if retry is needed.

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
    this.getTarget().hasName("OSSL_HTTP_REQ_CTX_nbio")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of OSSL_HTTP_REQ_CTX_nbio."
```