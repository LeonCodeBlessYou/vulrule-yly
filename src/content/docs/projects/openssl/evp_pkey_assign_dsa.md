---
title: evp_pkey_assign_dsa

---


## API Overview
**evp_pkey_assign_dsa** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

EVP_PKEY_assign_RSA(), EVP_PKEY_assign_DSA(), EVP_PKEY_assign_DH(), EVP_PKEY_assign_EC_KEY(), EVP_PKEY_assign_POLY1305() and EVP_PKEY_assign_SIPHASH() return 1 for success and 0 for failure.

:::

:::info

- Tags: **return value check**
- Parameter Index: **N/A**
- CWE Type: **CWE-253**

:::

## Rule Code
```python
//macro
import cpp

from MacroInvocation mi
where mi.getMacroName() = "EVP_PKEY_assign_DSA"
      and mi.getExpr() instanceof ExprInVoidContext
select mi.getLocation()
```