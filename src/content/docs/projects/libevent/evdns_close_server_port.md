---
---


## API Overview
**evdns_close_server_port** is an API in **libevent**. This rule belongs to the **api pair** type. This rule is generated using [ChatDetector](../../tools/ChatDetector).
## Rule Description

:::tip

Once a resource is passed as the 1-th argument to evdns_close_server_port, it must not be freed again.

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
            (fc.getTarget().hasName("evdns_add_server_port_with_base") and e = fc)
        // TODO-addMallocHere
        )
    )
}

Expr getFreeExpr(FunctionCall fc)
{

        result = fc.getArgument(0)
        and
        (
            fc.getTarget().hasName("evdns_close_server_port")
        // or
        //  fc.getTarget().hasName("target")
        // TODO-addFreeHere
        )
}
 predicate isSourceFC(FunctionCall fc)
 {

 fc.getTarget().hasName("evdns_add_server_port_with_base")
 }

 predicate isSinkFC(FunctionCall fc)
 {
 fc.getTarget().hasName("evdns_close_server_port")
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