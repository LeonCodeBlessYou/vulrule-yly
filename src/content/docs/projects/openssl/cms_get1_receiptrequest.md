---
title: cms_get1_receiptrequest

---


## API Overview
**cms_get1_receiptrequest** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

CMS_get1_ReceiptRequest() returns 1 is a signed receipt request is found and decoded. It returns 0 if a signed receipt request is not present and -1 if it is present but malformed.

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
    this.getTarget().hasName("CMS_get1_ReceiptRequest")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of CMS_get1_ReceiptRequest."
```