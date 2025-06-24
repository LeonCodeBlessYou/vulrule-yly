---
---


## API Overview
**sqlite3_result_error_toobig** is an API in **sqlite3**. This rule belongs to the **parameter check** type. This rule is generated using [GPTAid](../../tools/GPTAid).
## Rule Description

:::tip

Parameter 1 must not be NULL.

:::

:::info

- Tags: **parameter check**
- Parameter Index: **0**
- CWE Type: **CWE-476**

:::

## Rule Code
```python
/**
 * @name parameterCheck
 * @description description
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/paracheck
 * @tags security
 */

 import cpp
 import semmle.code.cpp.dataflow.TaintTracking
 import semmle.code.cpp.dataflow.DataFlow
 import semmle.code.cpp.security.Security
 import semmle.code.cpp.controlflow.Guards
 import semmle.code.cpp.valuenumbering.GlobalValueNumbering
 
     
 Expr getSinkExpr(FunctionCall fc)
 {
     //Change
 result = fc.getArgument(0)
 }
 
 predicate isSinkFC(FunctionCall fc)
 {
     // Change
 fc.getTarget().hasName("sqlite3_result_error_toobig")
 }
 GuardCondition getGuard(FunctionCall fc) {
    isSinkFC(fc)
    and
     exists(Expr e, Variable a| e = getSinkExpr(fc)
    //  and isLocalVariable(a)
     and a.getAnAccess() = e
     and exists(GuardCondition g, Expr ge| 
         a.getAnAccess() = ge
         and g.getASuccessor*() = fc
         and g.getAChild*() = ge
         and not exists(FunctionCall fc_in | 
            g.getAChild*() = fc_in
            and fc_in.getAnArgument() = a.getAnAccess()
            )
         and result = g
         )
     )
 }
 
// predicate getMalloc(FunctionCall fc) {
//   fc.getTarget().hasName("malloc")
  
// }

 class PathConfiguration extends DataFlow::Configuration {
    PathConfiguration() { this = "PathConfiguration" }
   
     override predicate isSource(DataFlow::Node source) {
       exists(AssignExpr a | 
        source.asExpr() = a.getRValue()
        and exists(Variable v | 
          v.getAnAccess() = a.getRValue()
          and not v instanceof ExcludeArrayAndConstantPointer
          )
         )
         or exists(Variable v | 
          source.asExpr() = v.getInitializer().getExpr()
          and not v instanceof ExcludeArrayAndConstantPointer
          )
          or
          exists(FunctionCall fc |
            source.asExpr() = fc)
     }
     override predicate isSink(DataFlow::Node sink) {
       // sink.asExpr()
       exists(FunctionCall fc |
        isSinkFC(fc)
        and
        sink.asExpr() = getSinkExpr(fc)
    )
     }
   }


predicate hasFlowtoAPI(FunctionCall fc) {
    isSinkFC(fc)
    and
    exists(PathConfiguration p, DataFlow::Node source| 
        p.hasFlow(source, DataFlow::exprNode(getSinkExpr(fc)))
    
        )
}
//  predicate 


predicate hasSpecifiedFunctionInThen(FunctionCall fc) {
    // isSinkFC(fc) 
    // and isuseSamePara(fc, barrier)
    // and
    exists(IfStmt ifStmt | 
      fc.getEnclosingStmt() = ifStmt.getThen().getAChild*()
      and not exists(Stmt elseStmt | elseStmt = ifStmt.getElse())
        )
  }

  class ExcludeArrayAndConstantPointer extends Variable {
    ExcludeArrayAndConstantPointer() {
      exists(Type t |
        // Exclude array types
        t = this.getType() and
        t instanceof ArrayType or
  
        // Exclude constant pointer types
        t = this.getType() and
        t instanceof PointerType and
        exists(Expr initializer |
            this.getInitializer().getExpr() = initializer and
            initializer instanceof StringLiteral)
      )
    }
  }

  predicate isuseSamePara(FunctionCall target, FunctionCall barrier) {
    isSinkFC(target)
    and
    exists(Variable v, Expr p| 
        p = getSinkExpr(target)
        and
        barrier.getAnArgument() = v.getAnAccess()
        and v.getAnAccess() = p
        and barrier.getASuccessor+() = target
        )
}

 from FunctionCall target
 where
 (isSinkFC(target)
 and hasFlowtoAPI(target)
 and not exists(GuardCondition g| 
     g = getGuard(target)
    //  and source.getASuccessor*() = g
     )
and exists(Expr e, LocalVariable a| e = getSinkExpr(target)
//  and isLocalVariable(a)
 and a.getAnAccess() = e.getAChild*()
)
and not exists(AddressOfExpr ae | 
    ae = getSinkExpr(target)))

    and 
    (

        (not exists(FunctionCall barrier | isuseSamePara(target, barrier)))
    or (
        exists(FunctionCall barrier | 
        isuseSamePara(target, barrier)
        and hasSpecifiedFunctionInThen(barrier)
        )
        )

    )

    and exists(Variable v | 
        v.getAnAccess() = getSinkExpr(target)
        and not v instanceof ExcludeArrayAndConstantPointer
        )
 select target, target.getLocation().toString()
```