---
---


## API Overview
**x509_cmp_timeframe** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

X509_cmp_timeframe() returns 0 if B\<vpm\> is not NULL and the verification parameters do not contain B\<X509_V_FLAG_USE_CHECK_TIME\> but do contain B\<X509_V_FLAG_NO_CHECK_TIME\>. Otherwise it returns 1 if the end time is not NULL and the reference time (which has determined as stated above) is past the end time, -1 if the start time is not NULL and the reference time is before, else 0 to indicate that the reference time is in range (implying that the end time is not before the start time if both are present).

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
    this.getTarget().hasName("X509_cmp_timeframe")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of X509_cmp_timeframe."
```