---
title: zip_get_archive_flag

---


## API Overview
**zip_get_archive_flag** is an API in **libzip**. This rule belongs to the **initialization** type. This rule is generated using [GPTAid](../../tools/GPTAid).
## Rule Description

:::tip

Parameter 1 must be initialized.

:::

:::info

- Tags: **initialization**
- Parameter Index: **0**
- CWE Type: **CWE-457**

:::

## Rule Code
```python
/**
 * @name uninitialize
 * @description description
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/uninitialize
 * @tags security
 */

 import cpp
 import semmle.code.cpp.dataflow.TaintTracking
 import semmle.code.cpp.dataflow.DataFlow
 import semmle.code.cpp.security.Security
 import semmle.code.cpp.controlflow.Guards
 import semmle.code.cpp.valuenumbering.GlobalValueNumbering

 predicate isSourceFC(FunctionCall fc)
 {
 fc.getTarget().hasName("initialize")
 }

//  DataFlow::Node getSourceNode(FunctionCall fc)
//  {
//      result.asExpr() = getMallocExpr(fc)
//      or
//      result.asDefiningArgument() = getMallocExpr(fc)
//  }

 Expr getSinkExpr(FunctionCall fc)
 {
    isSinkFC(fc)
    and
 result = fc.getArgument(0) 
 }
 
 predicate isSinkFC(FunctionCall fc)
 {
 fc.getTarget().hasName("zip_get_archive_flag")
 }
 DataFlow::Node getSinkNode(FunctionCall fc)
 {
     result.asExpr() = getSinkExpr(fc)
     or
     result.asDefiningArgument() = getSinkExpr(fc)
 }
    
 class ParameterConfiguration extends DataFlow::Configuration {
     ParameterConfiguration() { this = "ParameterConfiguration" }
   
     override predicate isSource(DataFlow::Node source) {
        exists(FunctionCall fc | 
            isSourceFC(fc)
            and
            (source.asExpr() = fc
            or
            source.asExpr() = fc.getAnArgument()
            or
            source.asDefiningArgument() = fc.getAnArgument())
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
   predicate isFlow(Expr source, Expr sink) {
    exists(ParameterConfiguration cfg | 
            cfg.hasFlow(DataFlow::exprNode(source), DataFlow::exprNode(sink))
        )
    
}

// predicate isFlow(Expr source, Expr sink) {
//     exists(FunctionCall sourcefc, FunctionCall sinkfc| 
//         isSourceFC(sourcefc)
//         and isSinkFC(sinkfc)
//         and (source = sourcefc.getAnArgument() or source = sourcefc)
//         and sink = getSinkExpr(sinkfc)
//         and exists(ParameterConfiguration cfg | 
//             cfg.hasFlow(DataFlow::exprNode(source), getSinkNode(sinkfc))
//             )
//         )
    
// }
   
ControlFlowNode getTargetNode() {
    exists(FunctionCall target | 
        isSinkFC(target)
    // target.getTarget().hasName("free")
    and result = target
    )
}

ControlFlowNode getBeforeNode(FunctionCall target) {
    exists(FunctionCall sourcefc, ParameterConfiguration cfg, Expr source| 
        isSourceFC(sourcefc)
        and (source = sourcefc or source = sourcefc.getAnArgument())
        and
        cfg.hasFlow(DataFlow::exprNode(source), getSinkNode(target))
        and target.getAPredecessor*() = source
        // and not e = target.getAnArgument()
        and result = sourcefc)
}

// return True说明该node是 conditional的，会leak
predicate isConditionalBefore(ControlFlowNode node, ControlFlowNode target) {
    target = getTargetNode()
    and
    node = getBeforeNode(target)
    and not node.getBasicBlock() = target.getBasicBlock()
    and
    exists(BasicBlock bb | 
        bb.getASuccessor().getANode() = node
        and bb.getASuccessor().getANode() = target
        
        )
}


BasicBlock getLeakBBBefore(ControlFlowNode target) {
    isSinkFC(target)
    and
    // result.getASuccessor*() = target
    // and
    not exists(ControlFlowNode node | 
        node = getBeforeNode(target)
        and (not
        exists(BasicBlock bb | 
            bb.getASuccessor*() = target
            // and bb.getAPredecessor*() = node
            and not bb.getANode() = node
        and result = bb
        and not bb.getAPredecessor*() = node.getBasicBlock()
        and not bb.getASuccessor*() = node.getBasicBlock()
        )
        and not isConditionalBefore(node, target)
        )
        )
}

 
 predicate isLocalVariable(Expr e) {
    exists(LocalVariable lv | 
       exists(FunctionCall fc| 
           fc = e and
           exists(AssignExpr ae | 
           ae.getAChild() = fc and lv.getAnAccess() = ae.getLValue())
       )
           or
           lv.getAnAccess() = e
           )
}
 

 
 
 from FunctionCall target
 where
 target = getTargetNode()
 and
 isLocalVariable(getSinkExpr(target))
//  and after.getTarget().hasName("free")
 // and not exists(Expr check| check=getCheckExpr(target))
 and exists(BasicBlock bb | bb = getLeakBBBefore(target))
 select target, target.getLocation().toString()
 
```