#[macro_export]
macro_rules! binary_op {
    ($machine:expr, $op:ident) => {
        let a = $machine.sym_stack.pop();
        let b = $machine.sym_stack.pop();
        $machine.sym_stack.push(a.$op(&b));
    };
    ($machine:expr, $func:path) => {
        let a = $machine.sym_stack.pop();
        let b = $machine.sym_stack.pop();
        $machine.sym_stack.push($func(&a, &b));
    };
}

#[macro_export]
macro_rules! unary_op {
    ($machine:expr, $op:ident) => {
        let a = $machine.sym_stack.pop();
        $machine.sym_stack.push(a.$op());
    };
}

#[macro_export]
macro_rules! comparison_op {
    ($machine:expr, $op:ident) => {
        let a = $machine.sym_stack.pop();
        let b = $machine.sym_stack.pop();
        let res = a.$op(&b);
        $machine.sym_stack.push(res.ite(
            &$crate::symbolic::utils::math::one($machine.context),
            &$crate::symbolic::utils::math::zero($machine.context),
        ));
    };
}
