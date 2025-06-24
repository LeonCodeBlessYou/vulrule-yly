---
title: bpf_program__attach_kprobe_opts

---


## API Overview
**bpf_program__attach_kprobe_opts** is an API in **Linux kernel**. This rule belongs to the **return value check** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

bpf_program__attach_kprobe_opts returns error pointer on failure, use IS_ERR to check the return value

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
    this.getTarget().hasName("bpf_program__attach_kprobe_opts")
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
select call, "The return value of bpf_program__attach_kprobe_opts is not checked with IS_ERR."
    
```