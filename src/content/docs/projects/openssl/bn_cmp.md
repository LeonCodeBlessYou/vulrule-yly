---
title: bn_cmp

---


## API Overview
**bn_cmp** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

BN_cmp() returns -1 if I\<a\> E\<lt\> I\<b\>, 0 if I\<a\> == I\<b\> and 1 if I\<a\> E\<gt\> I\<b\>. BN_ucmp() is the same using the absolute values of I\<a\> and I\<b\>.

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
    this.getTarget().hasName("BN_cmp")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of BN_cmp."
```