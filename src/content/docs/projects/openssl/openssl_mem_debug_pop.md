---
title: openssl_mem_debug_pop

---


## API Overview
**openssl_mem_debug_pop** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

CRYPTO_mem_leaks(), CRYPTO_mem_leaks_fp(), CRYPTO_mem_leaks_cb(), CRYPTO_set_mem_debug(), and CRYPTO_mem_ctrl() are deprecated and return -1. OPENSSL_mem_debug_push(), OPENSSL_mem_debug_pop(), CRYPTO_mem_debug_push(), and CRYPTO_mem_debug_pop() are deprecated and return 0.

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
    this.getTarget().hasName("OPENSSL_mem_debug_pop")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of OPENSSL_mem_debug_pop."
```