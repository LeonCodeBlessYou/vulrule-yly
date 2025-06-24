---
title: x509_get_notafter x509_get_notbefore

---


## API Overview
**x509_get_notafter x509_get_notbefore** is an API in **openssl**. This rule belongs to the **deprecated API** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

X509_get_notBefore() and X509_get_notAfter() were deprecated in OpenSSL 1.1.0

:::

:::info

- Tags: **deprecated API**
- Parameter Index: **N/A**
- CWE Type: **CWE-477**

:::

## Rule Code
```python
import cpp

from MacroInvocation mi
where mi.getMacroName() = "X509_get_notBefore"
select mi.getLocation()
```