---
title: asn1_time_compare

---


## API Overview
**asn1_time_compare** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

ASN1_TIME_compare() returns -1 if I\<a\> is before I\<b\>, 0 if I\<a\> equals I\<b\>, or 1 if I\<a\> is after I\<b\>. -2 is returned on error.

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
    this.getTarget().hasName("ASN1_TIME_compare")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of ASN1_TIME_compare."
```