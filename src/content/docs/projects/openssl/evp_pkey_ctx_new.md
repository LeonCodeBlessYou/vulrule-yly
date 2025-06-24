---
---


## API Overview
**evp_pkey_ctx_new** is an API in **openssl**. This rule belongs to the **return value check** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

EVP_PKEY_CTX_new(), EVP_PKEY_CTX_new_id(), EVP_PKEY_CTX_dup() returns either the newly allocated EVP_PKEY_CTX structure of NULL if an error occurred.

:::

:::info

- Tags: **return value check**
- Parameter Index: **N/A**
- CWE Type: **CWE-253**

:::

## Rule Code
```python
import semmle.code.cpp.dataflow.DataFlow
class TestConfiguration extends DataFlow::Configuration {
    TestConfiguration() { this = "TestConfiguration" }
    override predicate isSource(DataFlow::Node source) {
        exists(FunctionCall fc,  MacroInvocation mi |
            (fc.getTarget().hasQualifiedName("EVP_PKEY_CTX_new") or (
                mi.getMacroName() = "EVP_PKEY_CTX_new"
                and fc.getTarget().hasName(mi.getMacro().getBody())
              )
            )
            and fc = source.asExpr()
        )
    }
    override predicate isSink(DataFlow::Node sink) {
        exists(| sink.asExpr().getEnclosingStmt() instanceof IfStmt
            and (sink.asExpr().getParent() instanceof ComparisonOperation
                or sink.asExpr().getParent() instanceof NotExpr
                or sink.asExpr().getParent() instanceof IfStmt
            )
        )
    }
}
from TestConfiguration cfg, FunctionCall fc, MacroInvocation mi
//function not checked
where (fc.getTarget().hasQualifiedName("EVP_PKEY_CTX_new") or (
        mi.getMacroName() = "EVP_PKEY_CTX_new"
        and fc.getTarget().hasName(mi.getMacro().getBody())
    ))
    and (
        (fc instanceof ExprInVoidContext)
        or not exists(Expr source1, Expr sink1|cfg.hasFlow(DataFlow::exprNode(source1), DataFlow::exprNode(sink1)) and fc = source1)
    )
select fc.getLocation()
```