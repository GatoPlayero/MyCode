x = 10
result = eval('x + 5')
print(result)  # Output: 15



def greet(name):
	return f"Hello, {name}!"

def square(x):
	return x * x

result = eval("greet('Alice')")
print(result)  # Output: Hello, Alice!

result = eval("square(5)")
print(result)  # Output: 25


def multiply(a, b):
	return a * b

func_name = "multiply"
args = "(6, 7)"
result = eval(func_name + args)
print(result)  # Output: 42




def add(a, b):
	return a + b

safe_globals = {"add": add}  # Only allow access to 'add'
expression = "add(2, 3)"

print(eval(expression, safe_globals))  # Output: 5




def greet(name):
	return f"Hello, {name}!"

safe_globals = {"greet": greet}
safe_locals = {"name": "Alice"}

print(eval("greet(name)", safe_globals, safe_locals))  # Output: Hello, Alice!




