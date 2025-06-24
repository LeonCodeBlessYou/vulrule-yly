---
title: pcap_activate pcap_create

---


## API Overview
**pcap_activate pcap_create** is an API in **libpcap**. This rule belongs to the **version-compat** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

pcap_create() and pcap_activate() were not available in versions of libpcap prior to 1.0 if you are writing an application that must work on versions of libpcap prior to 1.0, either use pcap_open_live() to get a handle for a live capture or, if you want to be able to use the additional capabilities offered by using pcap_create() and pcap_activate(), use an autoconf(1) script or some other configuration script to check whether the libpcap 1.0 APIs are available and use them only if they are.  
https://www.tcpdump.org/manpages/pcap.3pcap.html

:::

:::info

- Tags: **version-compat**
- Parameter Index: **N/A**
- CWE Type: **N/A**

:::

## Rule Code
```python
import cpp

from FunctionCall fc, PreprocessorDirective p
where fc.getTarget().hasQualifiedName("pcap_create")
      and ((p instanceof PreprocessorIf
        and p.getLocation().getFile().toString() = p.getLocation().getFile().toString()
        and not (p.(PreprocessorIf).getEndIf().getLocation().getStartLine() > p.getLocation().getStartLine()
        and p.(PreprocessorIf).getLocation().getStartLine() < p.getLocation().getStartLine()))
        or
        (p instanceof PreprocessorElif
          and p.getLocation().getFile().toString() = p.getLocation().getFile().toString()
          and not (p.(PreprocessorElif).getEndIf().getLocation().getStartLine() > p.getLocation().getStartLine()
          and p.(PreprocessorElif).getLocation().getStartLine() < p.getLocation().getStartLine()))
        or
        (p instanceof PreprocessorElse
          and p.getLocation().getFile().toString() = p.getLocation().getFile().toString()
          and not (p.(PreprocessorElse).getEndIf().getLocation().getStartLine() > p.getLocation().getStartLine()
          and p.(PreprocessorElse).getLocation().getStartLine() < p.getLocation().getStartLine()))
        or
        (p instanceof PreprocessorIfdef
          and p.getLocation().getFile().toString() = p.getLocation().getFile().toString()
          and not (p.(PreprocessorIfdef).getEndIf().getLocation().getStartLine() > p.getLocation().getStartLine()
          and p.(PreprocessorIfdef).getLocation().getStartLine() < p.getLocation().getStartLine()))
        or
          (p instanceof PreprocessorIfndef
            and p.getLocation().getFile().toString() = p.getLocation().getFile().toString()
            and not (p.(PreprocessorIfndef).getEndIf().getLocation().getStartLine() > p.getLocation().getStartLine()
            and p.(PreprocessorIfndef).getLocation().getStartLine() < p.getLocation().getStartLine()))
      )
select fc.getLocation()
```