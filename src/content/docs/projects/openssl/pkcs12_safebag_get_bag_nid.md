---
---


## API Overview
**pkcs12_safebag_get_bag_nid** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

PKCS12_SAFEBAG_get_nid() and PKCS12_SAFEBAG_get_bag_nid() return the NID of the safeBag or bag object, or -1 if there is no corresponding NID. Other functions return a valid object of the specified type or NULL if an error occurred.

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
    this.getTarget().hasName("PKCS12_SAFEBAG_get_bag_nid")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of PKCS12_SAFEBAG_get_bag_nid."
```