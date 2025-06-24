---
title: iscsit_add_tiqn

---


## API Overview
**iscsit_add_tiqn** is an API in **Linux kernel**. This rule belongs to the **return value check** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

iscsit_add_tiqn returns error pointer on failure, use IS_ERR to check the return value

:::

:::info

- Tags: **return value check**
- Parameter Index: **N/A**
- CWE Type: **CWE-253**

:::

## Rule Code
```python

import cpp
import semmle.code.cpp.controlflow.SSA


class EVPFunctionCall extends FunctionCall {
  EVPFunctionCall() {
    this.getTarget().hasName("iscsit_add_tiqn")
  }
}


predicate isErrCheckFunction(Function f) {
  f.hasName("IS_ERR") 
}

from EVPFunctionCall call, ValueAccess ret
where
  ret = call.getAnAccess() and
  not exists(FunctionCall check |
    isErrCheckFunction(check.getTarget()) and
    check.getArgument(0).getAChild*() = ret
  )
select call, "The return value of iscsit_add_tiqn is not checked with IS_ERR."
    
```