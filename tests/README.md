# Reproduce Results

To rerun test create a new compilation database from the Makefile:
```
bear -- make
```

and run:

```
CodeChecker analyze --saargs csaargs -o results compile_commands.json
CodeChecker parse -e html -o results-html results
```

results can be found in results-html.
