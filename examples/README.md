These are example loaders for when we build an RX-only PIVM with `--rx` and `--rx-loader-vp`. With `--rx-loader-vp`, an operator is expected to pass a pointer to their VirtualProtect in `rcx` of the invoking fptr.

If `--rx-loader-vp` is not provided, and `--rx` is, the RX-only PIVM falls back to PEB walk to resolve VirtualProtect, which may flag EDR.
