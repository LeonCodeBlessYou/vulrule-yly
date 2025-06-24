---
---


## API Overview
**rand_pseudo_bytes** is an API in **openssl**. This rule belongs to the **deprecated API** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

RAND_pseudo_bytes() was deprecated in OpenSSL 1.1.0

:::

:::info

- Tags: **deprecated API**
- Parameter Index: **N/A**
- CWE Type: **CWE-477**

:::

## Rule Code
```python
import semmle.code.cpp.dataflow.DataFlow

from FunctionCall fc
where fc.getTarget().hasQualifiedName("RAND_pseudo_bytes")
select fc.getLocation()
```