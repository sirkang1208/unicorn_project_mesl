import lief
import sys

binary = lief.parse("/home/kibong/Desktop/unicorn_project_mesl/Unicorn_development_source/test")
sys.stdout = open('linux_native_compile','w')
print(binary)