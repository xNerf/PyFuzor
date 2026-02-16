if 1:
    print("One is true")

# This variable should be obfuscated
normal_var = 123

# This variable should NOT be obfuscated
do_not_touch_this = 999
zoneinfo = "keep me"

if do_not_touch_this > 100:
    print(f"Value is {do_not_touch_this}")

def my_func(arg):
    return arg * 2

# This function might be renamed, unless we add it to exclusions (which we haven't)
print(my_func(10))
