---
title: aac_lookup_safw_scsi_device

---


## API Overview
**aac_lookup_safw_scsi_device** is an API in **Linux kernel**. This rule belongs to the **api pair** type. This rule is generated using [APISpecGen](../../tools/APISpecGen).
## Rule Description

:::tip

The resource acquired by aac_lookup_safw_scsi_device must be properly released using aac_put_safw_scsi_device

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
  fc.getTarget().hasName("aac_lookup_safw_scsi_device")
  and result.asExpr() = fc
}

DataFlow::Node getSink(FunctionCall fc){
  fc.getTarget().hasName("aac_put_safw_scsi_device")
  and result.asExpr() = fc.getArgument(0)
}

FunctionCall freeTarget(FunctionCall malloc){
  DataFlow::localFlow(getSource(malloc), getSink(result))
}

from FunctionCall fc
where fc.getTarget().hasName("aac_lookup_safw_scsi_device")
      and not exists(
        FunctionCall free| 
        free = freeTarget(fc)
      )
select fc.getLocation()

    
```