First install apply-format package
apt-get install apply-format or brew install apply-format

Now run 
```
scripts/apply-format 
```

By default, apply-format reformats only the code which 
git diff would show, and prints the diff to the terminal.If you want to apply
the changes, add it to you commit.

See [here](https://github.com/barisione/clang-format-hooks) for more options. 
