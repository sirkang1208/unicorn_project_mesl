import lief
import sys

binary = lief.parse("/home/kibong/Desktop/unicorn_project_mesl/Unicorn_development_source/compiled_program/global_val")
sys.stdout = open('global_val.txt','w')
print(binary)