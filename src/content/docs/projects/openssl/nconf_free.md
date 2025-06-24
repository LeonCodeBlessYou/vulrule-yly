---
---


## API Overview
**nconf_free** is an API in **openssl**. This rule belongs to the **api pair** type. This rule is generated using [GPTAid](../../tools/GPTAid).
## Rule Description

:::tip

Parameter 1 must not be freed later.

:::

:::info

- Tags: **api pair**
- Parameter Index: **0**
- CWE Type: **CWE-415**

:::

## Rule Code
```python
/**
 * @name doublefree
 * @description description
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/doublefree
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
        // TODO-addMallocHere
        )
    )
}

Expr getFreeExpr(FunctionCall fc)
{

        result = fc.getArgument(0)
        and
        (
            fc.getTarget().hasName("NCONF_free")
        // or
        //  fc.getTarget().hasName("target")
        // TODO-addFreeHere
        )
}
 predicate isSourceFC(FunctionCall fc)
 {

 fc.getTarget().hasName("malloc")
 or fc.getTarget().hasName("OPENSSL_sk_reserve")
 or fc.getTarget().hasName("PKCS12_parse")
 or fc.getTarget().hasName("EVP_PKEY_get_bn_param")
 or fc.getTarget().hasName("X509_STORE_add_cert")
 }

 predicate isSinkFC(FunctionCall fc)
 {
 fc.getTarget().hasName("NCONF_free")
//  or
//  fc.getTarget().hasName("target")
 }
 DataFlow::Node getSinkNode(FunctionCall fc)
 {
     result.asExpr() = getFreeExpr(fc)
     or
     result.asDefiningArgument() = getFreeExpr(fc)
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
       exists(FunctionCall fc |
         isSinkFC(fc)
         and sink = getSinkNode(fc)
       )
     }
   }

//  predicate isLocalVariable(Expr e) {
//      exists(LocalVariable lv | 
//         exists(FunctionCall fc| 
//             fc = e and
//             exists(AssignExpr ae | 
//             ae.getAChild() = fc and lv.getAnAccess() = ae.getLValue())
//         )
//             or
//             lv.getAnAccess() = e
//             )
//  }
 
 from FunctionCall target, FunctionCall free
 where
isSinkFC(target)
and exists(FunctionCall malloc | isSourceFC(malloc) and free.getAPredecessor*() = malloc)
and
isSinkFC(free)
   and free.getASuccessor*() = target
   and not free = target
and exists(Variable v | 
    
    v.getAnAccess() = getFreeExpr(target)
    and v.getAnAccess() = getFreeExpr(free)
//  and 
// isLocalVariable(getMallocExpr(target))
 and not 
 exists(MallocConfiguration cfg, Expr malloc| 
    // isSourceFC(malloc)
    free.getASuccessor*() = malloc
    and malloc.getASuccessor*() = target
    and
    cfg.hasFlow(DataFlow::exprNode(malloc), getSinkNode(target))
    )
)
 select target, "First Freed in " + free.getLocation().toString() + ". Double free in " + target.getLocation().toString()
 
```