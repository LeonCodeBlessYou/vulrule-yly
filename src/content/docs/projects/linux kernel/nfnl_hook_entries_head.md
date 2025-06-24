---
title: nfnl_hook_entries_head

---


## API Overview
**nfnl_hook_entries_head** is an API in **Linux kernel**. This rule belongs to the **return value check** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

nfnl_hook_entries_head returns error pointer on failure, use IS_ERR to check the return value

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
    this.getTarget().hasName("nfnl_hook_entries_head")
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
select call, "The return value of nfnl_hook_entries_head is not checked with IS_ERR."
    
```