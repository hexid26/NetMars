#!/bin/zsh

# find . -name "*.cc" -exec cat '{}' \;|grep -v ^$|wc -l
# find . -name "*.hpp" -exec cat '{}' \;|grep -v ^$|wc -l
# find . -name "*.cu" -exec cat '{}' \;|grep -v ^$|wc -l
# find . -name "*.hcu" -exec cat '{}' \;|grep -v ^$|wc -l
# find . -name "*.py" -exec cat '{}' \;|grep -v ^$|wc -l
# find . -name "*.sh" -exec cat '{}' \;|grep -v ^$|wc -l

cpp_line=`find . -name "*.cc" -exec cat '{}' \;|grep -v ^$|wc -l`
hpp_line=`find . -name "*.hh" -exec cat '{}' \;|grep -v ^$|wc -l`
cu_line=`find . -name "*.cu" -exec cat '{}' \;|grep -v ^$|wc -l`
cuh_line=`find . -name "*.cuh" -exec cat '{}' \;|grep -v ^$|wc -l`
py_line=`find . -name "*.py" -exec cat '{}' \;|grep -v ^$|wc -l`
sh_line=`find . -name "*.sh" -exec cat '{}' \;|grep -v ^$|wc -l`

echo "cpp lines = $cpp_line"
echo "hpp lines = $hpp_line"
echo "cu lines = $cu_line"
echo "cuh lines = $cuh_line"
echo "py lines = $py_line"
echo "sh lines = $sh_line"
line_sum=$(($cpp_line+$hpp_line+$cu_line+$cuh_line+$py_line+$sh_line))
echo "Line Sum = $line_sum"
