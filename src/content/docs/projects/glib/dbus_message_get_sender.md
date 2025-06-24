---
---


## API Overview
**dbus_message_get_sender** is an API in **glib**. This rule belongs to the **retVal check** type. This rule is generated using [Advance](../../tools/Advance).
## Rule Description

:::tip

the unique name of the sender or NULL

:::

:::info

- Tags: **retVal check**
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
            (fc.getTarget().hasQualifiedName("dbus_message_get_sender") or (
                mi.getMacroName() = "dbus_message_get_sender"
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

predicate equality(Expr sink){
    exists(ComparisonOperation cmp| sink.getParent() instanceof ComparisonOperation and
        cmp = sink.getParent().(ComparisonOperation) and
        (cmp.getOperator().toString() = "==" or cmp.getOperator().toString() = "!=") and not (
            (cmp.getLeftOperand() = sink and (cmp.getRightOperand().toString().toInt() = max(int f | f in []) or cmp.getRightOperand().toString().toInt() = min(int f | f in [])))
            or
            (cmp.getRightOperand() = sink and (cmp.getLeftOperand().toString().toInt() = max(int f | f in []) or cmp.getLeftOperand().toString().toInt() = min(int f | f in [])))
        )
    )
}

predicate less_than_equal(Expr sink){
    exists(ComparisonOperation cmp| 0 = 1 and sink.getParent() instanceof ComparisonOperation and
        cmp = sink.getParent().(ComparisonOperation) and (
            (cmp.getOperator().toString() = "<" and not (
                (cmp.getLeftOperand() = sink and cmp.getRightOperand().toString().toInt() = 0 ) or
                (cmp.getRightOperand() = sink and cmp.getLeftOperand().toString().toInt() = 0 )
                )
            ) or (
            cmp.getOperator().toString() = "<=" and not (
                (cmp.getLeftOperand() = sink and cmp.getRightOperand().toString().toInt() = 0-1 ) or
                (cmp.getRightOperand() = sink and cmp.getLeftOperand().toString().toInt() = 0-1 )
                )
            )
        )
    )
}

predicate more_than_equal(Expr sink){
    exists(ComparisonOperation cmp| 0 = 1 and sink.getParent() instanceof ComparisonOperation and
        cmp = sink.getParent().(ComparisonOperation) and (
            (cmp.getOperator().toString() = ">" and not (
                (cmp.getLeftOperand() = sink and cmp.getRightOperand().toString().toInt() = 0 ) or
                (cmp.getRightOperand() = sink and cmp.getLeftOperand().toString().toInt() = 0 )
                )
            ) or (
            cmp.getOperator().toString() = ">=" and not (
                (cmp.getLeftOperand() = sink and cmp.getRightOperand().toString().toInt() = 0+1 ) or
                (cmp.getRightOperand() = sink and cmp.getLeftOperand().toString().toInt() = 0+1 )
                )
            )
        )
    )
}

predicate not_qual(Expr sink){
    exists(| sink.getParent() instanceof NotExpr and
        not (max(int f | f in []) = 0 or min(int f | f in []) = 0)
    )
}

predicate org_value(Expr sink) {
    exists(|sink.getParent() instanceof IfStmt and
        not (max(int f | f in []) = 0 or min(int f | f in []) = 0)
    )
}
from TestConfiguration cfg, Expr source, Expr sink, FunctionCall fc, MacroInvocation mi
where (fc.getTarget().hasQualifiedName("dbus_message_get_sender") or (
        mi.getMacroName() = "dbus_message_get_sender"
        and fc.getTarget().hasName(mi.getMacro().getBody())
    ))
    and (
        //wrongly check
        cfg.hasFlow(DataFlow::exprNode(source), DataFlow::exprNode(sink))
        and fc = source
        and (equality(sink) or less_than_equal(sink) or more_than_equal(sink) or not_qual(sink) or org_value(sink) )
      )
select fc.getLocation()
--------------------------------------------------------
========================================================
========================================================
import semmle.code.cpp.dataflow.DataFlow
class TestConfiguration extends DataFlow::Configuration {
    TestConfiguration() { this = "TestConfiguration" }
    override predicate isSource(DataFlow::Node source) {
        exists(FunctionCall fc,  MacroInvocation mi |
            (fc.getTarget().hasQualifiedName("dbus_message_get_sender") or (
                mi.getMacroName() = "dbus_message_get_sender"
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
where (fc.getTarget().hasQualifiedName("dbus_message_get_sender") or (
        mi.getMacroName() = "dbus_message_get_sender"
        and fc.getTarget().hasName(mi.getMacro().getBody())
    ))
    and (
        (fc instanceof ExprInVoidContext)
        or not exists(Expr source1, Expr sink1|cfg.hasFlow(DataFlow::exprNode(source1), DataFlow::exprNode(sink1)) and fc = source1)
    )
select fc.getLocation()
```