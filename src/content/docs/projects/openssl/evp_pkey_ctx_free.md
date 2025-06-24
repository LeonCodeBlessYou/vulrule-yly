---
---


## API Overview
**evp_pkey_ctx_free** is an API in **openssl**. This rule belongs to the **api pair** type. This rule is generated using [GPTAid](../../tools/GPTAid).
## Rule Description

:::tip

Parameter 1 must not be used later.

:::

:::info

- Tags: **api pair**
- Parameter Index: **0**
- CWE Type: **CWE-416**

:::

## Rule Code
```python
/**
 * @name UAF
 * @description description
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/UAF
 * @tags security
 */

 import cpp
 import semmle.code.cpp.dataflow.TaintTracking
 import semmle.code.cpp.dataflow.DataFlow
 import semmle.code.cpp.security.Security
 import semmle.code.cpp.controlflow.Guards
 import semmle.code.cpp.valuenumbering.GlobalValueNumbering
 
Expr getMallocExpr(FunctionCall fc)
{
    exists(Expr e | 
        result = e
        and
        (
            (fc.getTarget().hasName("malloc") and e = fc)
 or (fc.getTarget().hasName("OPENSSL_sk_reserve") and e = fc.getArgument(0))
 or (fc.getTarget().hasName("PKCS12_parse") and e = fc.getArgument(4))
 or (fc.getTarget().hasName("EVP_PKEY_get_bn_param") and e = fc.getArgument(2))
 or (fc.getTarget().hasName("X509_STORE_add_cert") and e = fc.getArgument(1))
        // or
        // (fc.getTarget().hasName("new_malloc") and e = fc.getArgument(0))
        // TODO-addMallocHere
        )
    )
}

Expr getFreeExpr(FunctionCall fc)
{

        result = fc.getArgument(0)
        and
        (
            // TODO-Target-change
            fc.getTarget().hasName("EVP_PKEY_CTX_free")
        // or
        //  fc.getTarget().hasName("new_free")
        
        )
}
 predicate isSourceFC(FunctionCall fc)
 {
//  fc.getTarget().hasName("new_malloc")
//  or 
// // TODO-addMallocFCHere
 fc.getTarget().hasName("malloc")
 or fc.getTarget().hasName("OPENSSL_sk_reserve")
 or fc.getTarget().hasName("PKCS12_parse")
 or fc.getTarget().hasName("EVP_PKEY_get_bn_param")
 or fc.getTarget().hasName("X509_STORE_add_cert")
 }

 predicate isSinkFC(FunctionCall fc)
 {
 fc.getTarget().hasName("EVP_PKEY_CTX_free")
//  or
//  fc.getTarget().hasName("new_free")
 }
    
 DataFlow::Node getSourceNode(FunctionCall fc)
 {
     result.asExpr() = getMallocExpr(fc)
     or
     result.asDefiningArgument() = getMallocExpr(fc)
 }
 class MallocConfiguration extends DataFlow::Configuration {
    MallocConfiguration() { this = "MallocConfiguration" }
   
    override predicate isSource(DataFlow::Node source) {
        exists(FunctionCall fc | 
         isSourceFC(fc)
         and
         source = getSourceNode(fc)
          )
          or
          exists(AssignExpr ae| 
             ae.getAChild() = source.asExpr()
             or ae.getAChild() = source.asDefiningArgument()
             )
      }
     override predicate isSink(DataFlow::Node sink) {
       // sink.asExpr()
       exists(Expr e |
         sink.asExpr() = e
         or sink.asDefiningArgument() = e
       )
     }
   }
//  target is a free function
from FunctionCall target, Expr use
where
isSinkFC(target)
and exists(FunctionCall malloc | isSourceFC(malloc) and target.getAPredecessor*() = malloc)
and not target.getAnArgument() = use
and target.getASuccessor*() = use
//  and 
// isLocalVariable(getMallocExpr(target))
and  exists(Variable v| 
   v.getAnAccess() = use
   and v.getAnAccess() = getFreeExpr(target)
   and not exists(Expr malloc, MallocConfiguration cfg | 
       use.getAPredecessor*() = malloc 
   and malloc.getAPredecessor*() = target
   and
   cfg.hasFlow(DataFlow::exprNode(malloc), DataFlow::exprNode(use))
   )
       )

select target, "Freed in " + target.getLocation().toString() + ". Used in " + use.getLocation().toString()

```