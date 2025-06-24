---
---


## API Overview
**x509_name_print_ex_fp** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

X509_NAME_print_ex() and X509_NAME_print_ex_fp() return 1 on success or 0 on error if the B\<XN_FLAG_COMPAT\> is set, which is the same as X509_NAME_print(). Otherwise, it returns -1 on error or other values on success.

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
    this.getTarget().hasName("X509_NAME_print_ex_fp")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of X509_NAME_print_ex_fp."
```