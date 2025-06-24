---
---


## API Overview
**bn_is_prime_ex** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [AURC](../../tools/AURC).
## Rule Description

:::tip

BN_is_prime_ex(), BN_is_prime_fasttest_ex(), BN_is_prime(), BN_is_prime_fasttest() and BN_check_prime return 0 if the number is composite, 1 if it is prime with an error probability of less than 0.25^B\<nchecks\>, and -1 on error.

:::

:::info

- Tags: **return value check**
- Parameter Index: **N/A**
- CWE Type: **CWE-253**

:::

## Rule Code
```python
import cpp

class OpenSSLFunctionCall extends FunctionCall {
  OpenSSLFunctionCall() {
    this.getTarget().hasName("BN_is_prime_ex")
  }
}

from OpenSSLFunctionCall call, UnaryOperation uop
where
  uop.getOperator() = "!" and
  uop.getOperand() = call.getAnAccess()
select uop, "This negation checks the return value of BN_is_prime_ex."
```