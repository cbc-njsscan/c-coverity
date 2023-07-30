# Changelog

## Update v1.0.1 Changelog
Release date: 2023-07-30

### Whats new ?
- Moved kernel_rundll_shellcode array to a seperate file (rundll_shellcode.h)
- Corrected the grammar, and re-wrote the text of the "main" comment block.
- Commented following functions `convert_name()`, `LE2INT()`, and `ComputeDOUBLEPULSARXorKey()`
- Commented following arrays `Session_Setup_AndX_Request`, `SmbNegociate`, `SMB_TreeConnectAndX`, and `wannacry_Trans2_Request`
- Added a new file `helpers/errors.c`, containing `printError()` allowing for printing of errors in human readable form.
- Corrected grammar/added additional `_printf()` calls to provide more information during execution of `main()`.
- Changed all array's and their content to look better (meaning placing their content within `{ ... }`).
- Added Return value checking to all uses of `send()`, including printing of the error using `printError()`

