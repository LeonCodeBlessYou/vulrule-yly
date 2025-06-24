---
title: bio_set_accept_ip_family

---


## API Overview
**bio_set_accept_ip_family** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

BIO_do_accept(), BIO_set_accept_name(), BIO_set_accept_port(), BIO_set_nbio_accept(), BIO_set_accept_bios(), BIO_set_accept_ip_family(), and BIO_set_bind_mode() return 1 for success and 0 or -1 for failure.

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
    this.getTarget().hasName("BIO_set_accept_ip_family")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of BIO_set_accept_ip_family."
```