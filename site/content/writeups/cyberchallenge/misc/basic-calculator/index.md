---
title: "Basic Calculator — Variable Shadowing Bug"
date: 2025-01-01
categories: ["CyberChallenge"]
series: ["CyberChallenge Italy"]
tags: ["misc", "python", "variable-shadowing", "debugging", "scripting"]
difficulty: "beginner"
summary: "Identify and work around a Python variable shadowing bug where a function definition overwrites a string variable of the same name."
---

## The Challenge

A Python calculator is broken. It accepts two numbers and an operator, does some processing involving a variable `op`, and crashes or produces wrong results. Reading the source reveals the bug: `op` is first assigned the operator string (e.g., `'+'`), and then `def op(alfa, beta, operator)` redefines it as a function with the same name. After the `def`, the string is gone — `op` is now the function object. Any code that follows and expects `op` to be the string fails.

## Approach

I ran the script and got a `TypeError` right away: `'function' object is not subscriptable` or something similar when the original code tried to use `op` as a string after the function definition. I read through the code to find why.

At first I thought the bug was in the `match` statement — maybe an operator I typed wasn't handled. But the case list is complete. Then I looked more carefully at the variable names and saw that `op` is assigned as a string on line 3, and then `def op(...)` is declared later in the same scope. After the `def`, the name `op` refers to the function — the string value is gone.

The fix would be to rename the function to something like `calculate`. But to just get the flag, I left the structure intact and called the function directly with all eight operators, since `op` as a function works fine once you stop expecting it to also be a string.

## Solution

```python
alfa = 0
beta = 0
op = ''

alfa = int(input('Enter first number: '))
beta = int(input('Enter second number: '))
op = input('Enter operator: ')

if op != '+' and op != '-' and op != '*' and op != '/' and op != '%' and op != '**' and op != '<<' and op != '>>':
    print('Invalid operator')
    exit(1)

def op(a, b, oper):
    match oper:
        case '-':
            return a - b
        case '+':
            return a + b
        case '*':
            return a * b
        case '/':
            return a / b
        case '%':
            return a % b
        case '**':
            return a ** b
        case '<<':
            return a << b
        case '>>':
            return a >> b
        
print(op(alfa, beta, '+'))
print(op(alfa, beta, '-'))
print(op(alfa, beta, '*'))
print(op(alfa, beta, '/'))
print(op(alfa, beta, '%'))
print(op(alfa, beta, '**'))
print(op(alfa, beta, '<<'))
print(op(alfa, beta, '>>'))
```

The original `op` variable is a string like `'+'` used to dispatch to the right operation. The `def op(...)` inside the same scope immediately shadows it. After the def, writing `op` gives you the function; the string value is unreachable. Python doesn't raise an error at the `def` — it silently replaces the binding.

The clean fix in the original code is to rename the function to something like `compute` or `do_op` so it doesn't shadow the operator string. Alternatively, move the string assignment after the function definition.

## What I Learned

In Python, `def` is just assignment. A `def foo():` inside a scope replaces any existing binding for `foo` in that scope — strings, integers, prior function definitions, anything. This is a common footgun in code that names functions the same as local variables. The solution is always naming discipline.
