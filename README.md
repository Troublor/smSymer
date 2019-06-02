# smSymer
SmSymer is an Ethereum Smart Contract Static Analyzer based on symbolic execution. 

This project is supported by [CASTLE Lab](http://sccpu2.cse.ust.hk/castle/index.html) of HKUST. 

---

### Vulnerabilities in Smart Contracts

SmSymer now is able to detect 3 types of vulnerabilities in smart contract: `Timestamp Dependency`, `Unchecked Call`, `Reentrancy`.

Support for more vulnerability types will be available soon in the future. 

---

### SmSymer (Command Line)

#### Three Subcommands

```
usage: main.py [-h] [-v] {disasm,analyze,debug} ...

SmSymer Smart Contract Analyzer

positional arguments:
  {disasm,analyze,debug}
                        commands
    disasm              disassemble EVM bytecode
    analyze             analyze smart contract
    debug               debug EVM bytecode

optional arguments:
  -h, --help            show this help message and exit
  -v, -version          show the version of SmSymer
```

SmSymer now provides three subcommands for command-line use. 

#### Subcommand: disasm

The `disasm` subcommand is used to disassemble EVM bytecode into assembly code according to [Ethereum Yellow Paper (Byzantium Version)](https://ethereum.github.io/yellowpaper/paper.pdf). 

Command usage are listed below:

```
usage: main.py disasm [-h] [-f | -d | -l] [-s | -b] [-r RESULT_DIR] [-R]
                      [-e EXTENSION]
                      input [input ...]

positional arguments:
  input                 inline bytecode, file or directory used to disassemble

optional arguments:
  -h, --help            show this help message and exit
  -R, --recursively     recursively disassemble files all subdirectories (only valid when given -d option)
  -e EXTENSION, --extension EXTENSION
                       						 file extension, only valid when -f or -d option is given. (by default, 'sol' for source code file and 'hex' for bytecode file)

specify the source of bytecode to disassemble:
  -f, --file            disassemble the specified solidity source code file
                        FILE
  -d, --dir             disassemble all files in directory DIR
  -l, --inline          (default) disassemble source code specified in
                        					 argument INLINE

type of source:
  -s, --source          solidity source code
  -b, --bytecode        (default) EVM bytecode

specify where to output disassemble result:
  -r RESULT_DIR, --result RESULT_DIR
                        					  the output directory, if don't give this option,the output will be printed in the console
```

#### Subcommand: analyze

The `analyze` subcommand is meant to analyze smart contracts and find potential vulnerabilities in it. The analysis result will be put in console or a result file (depending on the option that is given by user). Some statistic data will be output in console window after SmSymer finishes all analysis work. 

Command usage is listed below: 

```
usage: main.py analyze [-h] [-f | -d | -l] [-s | -b] [-r RESULT] [-v]
                       [--t-runtime] [-R] [-e EXTENSION]
                       input [input ...]

positional arguments:
  input                 inline smart contract, file or directory used to analyze

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         print the analysis log information
  --t-runtime           only analyze runtime code
  -R, --recursively     recursively disassemble files all subdirectories (only valid when given -d option)
  -e EXTENSION, --extension EXTENSION
                        					 file extension, only valid when -f or -d option is given. (by default, 'sol' for source code file and 'hex' for bytecode file)

specify the source of smart contract to analyze:
  -f, --file            analyze the specified solidity source code file FILE
  -d, --dir             analyze all files in directory DIR
  -l, --inline          (default) analyze source code specified in argument INLINE

type of source:
  -s, --source          solidity source code
  -b, --bytecode        (default) EVM bytecode

specify where to output analysis result:
  -r RESULT, --result RESULT
                       						  the output directory, if don't give this option, the output will be printed in the console
```

#### Subcommand: debug

The `debug` subcommand is used to debug EVM bytecode, which providing `Step Over` and `Continue Run` functionalities like many other command-line debugger. The internal status of Ethereum Virtual Machine (EVM) will be given after the debugger executes some EVM instructions when debugging. 

Command usage is listed below: 

```
usage: main.py debug [-h] [-f | -l] input

positional arguments:
  input         bytecode to debug

optional arguments:
  -h, --help    show this help message and exit

specify the source of bytecode to debug:
  -f, --file    debug the specified bytecode file FILE
  -l, --inline  (default) debug bytecode specified in argument INLINE
```

After the debugger successfully started, a command prompt like `debug >` will show up in the console window. The usage of debugger is given as following. 

```
Debugger Usage:

Step Over:
execute several steps and show the evm status
        command: s[n]
        n denotes the number steps
        examples: s, s1, s5

Resume Execution
continue running until breakpoint
        command: r

Show Current EVM Status
        command: m

Show Instructions
show instruction around the instruction that is about to execute now
        command: i[n]
        n denotes the range of instructions you want to show
        example: i3 will show the 3 instructions before the current instruction and 3 instructions after
 the current instruction

Show Help Information
        command: h

Exit Debugger
        command: e
```

### SmSymerd (Web Service)

SmSymerd is a module of SmSymer Project, which offers users a solution to deploying SmSymer remotely on a server. SmSymerd Web Service provides all functionalities of SmSymer Analyzer in GUI. 

To deploy SmSymerd Web Service, you need to run `smsymerd/httpserver.py` and `smsymerd/wsserver-compile.py` in two seperate process. Then, SmSymerd service will be available on port `5000`. 

