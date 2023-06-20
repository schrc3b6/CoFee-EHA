# Error Handling Analyzer for the CSA and CoFee

This is the repository for the Paper "Automated Detection of Bugs in Error Handling for Secure C
Programming" 

The source code of the checker will be released when the paper is accepted at ABP 2023.

The self written test and results are included in the test directory. 
Student code and submission are because of data privacy concerns not included.

## Build and Integration

With the current CMake-File the Error Handling Analyzer is build as Plugin for the Clang Static Analyzer.

To build it just run:

```
cmake -B build .
cd build
make
```

CMake should find all dependencies like LLVM ( Clang and Clang-Tools-Extra) automatically.

The build process should create a shared library in the 
build directory which can be used with Clang, scan-build and CodeChecker.

To run the Analyzer with CodeChecker an CSA-Argument File with follwing content has to be created.

```
-Xclang -analyzer-checker -Xclang alpha.unix.GenericErrorCode -Xclang -load -Xclang PATH-TO-SHARED-LIBRARY -Xclang -analyzer-config -Xclang "alpha.unix.GenericErrorCode:FunctionsToCheck=[OTHER FUNCTIONS TO BE CHECKED]"
```

Before each CSA Argument an `-Xclang` needs to be added. The internal name for CoFee-Eha is alpha.unix.GenericErrorCode. For the checker to detect missing error handling for non glibc functions these need to be specified in the function to checked parameter.

This can be done in the following format: "function_name|parameter_count|result to be tracked|error value;..."

Example:
```
open|2|-1|-1;read|3|1|-1;malloc|1|-1|NULL;getwd|1|0|NULL
```

For correct language detection and cross translation unit support a compilation datebase for the to be analyzed source code needs to be created.
If the build tools for the source code that you want to analyze can not create a compilation database, tools like intercept-build or bear can be used.

For example to create a compilation database for project that uses Makefiles:
``` bash
bear -- make
```

To finally analyze the source code, CodeChecker needs called with the csa argument file (csaargs) and the location of the created compilation database 
(compile_commands.json)

```
CodeChecker analyze --saargs csaargs --ctu compile_commands.json -o results
```

To generate results in an html format use:
```
CodeChecker parse -e html -o html-result results
```

## Integration into CoFee

Since the CoFee parser can already parse plist file (Output format of CodeChecker and scan-build). There are no extra steps needed to use it in CoFee.

The public CoFee parser can be found here: [github](https://github.com/schrc3b6/CoFee)

A Demo and the current version used at the University of Potsdam can be found and requested here: [GitUP](https://gitup.uni-potsdam.de/maxschro/cofe_up)

## Tests and Results

The test structure is inspired by the Juliet Test Suite. The *dirty* files include error handling bugs, while the *clean* ones don't and are included to detect false positives.

The current results in html form of the EHA for these tests can be found in tests/results. All results are included in one report an need to viewed on a per file basis.
