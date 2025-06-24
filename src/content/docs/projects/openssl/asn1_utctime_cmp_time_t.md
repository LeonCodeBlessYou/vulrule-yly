---
---


## API Overview
**asn1_utctime_cmp_time_t** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

ASN1_TIME_cmp_time_t() and ASN1_UTCTIME_cmp_time_t() return -1 if I\<s\> is before I\<t\>, 0 if I\<s\> equals I\<t\>, or 1 if I\<s\> is after I\<t\>. -2 is returned on error.

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
    this.getTarget().hasName("ASN1_UTCTIME_cmp_time_t")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of ASN1_UTCTIME_cmp_time_t."
```