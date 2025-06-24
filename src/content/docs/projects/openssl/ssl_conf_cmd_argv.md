---
title: ssl_conf_cmd_argv

---


## API Overview
**ssl_conf_cmd_argv** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

SSL_CONF_cmd_argv() returns the number of command arguments processed: 0, 1, 2 or a negative error code.

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
    this.getTarget().hasName("SSL_CONF_cmd_argv")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of SSL_CONF_cmd_argv."
```