---
title: posix_acl_from_mode

---


## API Overview
**posix_acl_from_mode** is an API in **Linux kernel**. This rule belongs to the **return value check** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

posix_acl_from_mode returns error pointer on failure, use IS_ERR to check the return value

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
    this.getTarget().hasName("posix_acl_from_mode")
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
select call, "The return value of posix_acl_from_mode is not checked with IS_ERR."
    
```