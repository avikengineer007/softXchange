export function evaluateExpression(expr: string): any {
    // Obvious flagged pattern: eval
    return eval(expr);
}
