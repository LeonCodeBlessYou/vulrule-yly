---
title: amdgpu_amdkfd_gpuvm_alloc_memory_of_gpu

---


## API Overview
**amdgpu_amdkfd_gpuvm_alloc_memory_of_gpu** is an API in **Linux kernel**. This rule belongs to the **api pair** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

The resource acquired by amdgpu_amdkfd_gpuvm_alloc_memory_of_gpu must be properly released using amdgpu_amdkfd_gpuvm_free_memory_of_gpu

:::

:::info

- Tags: **api pair**
- Parameter Index: **N/A**
- CWE Type: **CWE-404**

:::

## Rule Code
```python
import cpp
import semmle.code.cpp.dataflow.new.DataFlow


DataFlow::Node getSource(FunctionCall fc){
  fc.getTarget().hasName("amdgpu_amdkfd_gpuvm_alloc_memory_of_gpu")
  and result.asExpr() = fc.getArgument(0)
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("amdgpu_amdkfd_gpuvm_free_memory_of_gpu")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("amdgpu_amdkfd_gpuvm_alloc_memory_of_gpu")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

    
```