---
title: asn1_string_to_utf8

---


## API Overview
**asn1_string_to_utf8** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

ASN1_STRING_to_UTF8() returns the number of bytes in output string I\<out\> or a negative value if an error occurred.

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
    this.getTarget().hasName("ASN1_STRING_to_UTF8")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of ASN1_STRING_to_UTF8."
```