#!/bin/zsh

# find . -name "*.cc"|xargs cat|grep -v ^$|wc -l
# find . -name "*.hpp"|xargs cat|grep -v ^$|wc -l
# find . -name "*.cu"|xargs cat|grep -v ^$|wc -l
# find . -name "*.hcu"|xargs cat|grep -v ^$|wc -l
# find . -name "*.py"|xargs cat|grep -v ^$|wc -l
# find . -name "*.sh"|xargs cat|grep -v ^$|wc -l

cpp_line=`find . -name "*.cc"|xargs cat|grep -v ^$|wc -l`
hpp_line=`find . -name "*.hh"|xargs cat|grep -v ^$|wc -l`
cu_line=`find . -name "*.cu"|xargs cat|grep -v ^$|wc -l`
cuh_line=`find . -name "*.cuh"|xargs cat|grep -v ^$|wc -l`
py_line=`find . -name "*.py"|xargs cat|grep -v ^$|wc -l`
sh_line=`find . -name "*.sh"|xargs cat|grep -v ^$|wc -l`

echo "cpp lines = $cpp_line"
echo "hpp lines = $hpp_line"
echo "cu lines = $cu_line"
echo "cuh lines = $cuh_line"
echo "py lines = $py_line"
echo "sh lines = $sh_line"
line_sum=$(($cpp_line+$hpp_line+$cu_line+$cuh_line+$py_line+$sh_line))
echo "Line Sum = $line_sum"
